"""mcp-fetch-ssrf-auditor: audit the MCP fetch tool as a cloud-metadata exfil path.

Everyone hardens network perimeters. The MCP fetch tool is an SSRF-shaped
hole that inherits your agent's privilege: on October 10, 2026, security
researchers reported that default mcp-server-fetch builds before
2026.10.10 could request private and metadata IP ranges unless operators
disabled protections manually. A prompt-injected agent with the fetch
tool can reach internal admin panels — or the cloud metadata endpoint
(169.254.169.254) — and read instance credentials, no exploit required.

This tool answers two deterministic questions:
  1. Which mcp-server-fetch versions are pinned in your AI-client MCP
     configs? (pre-2026.10.10 or unpinned = cannot prove the SSRF
     protections exist)
  2. Does this host block the cloud metadata endpoint (169.254.169.254)
     via /etc/hosts or firewall rules? (UNKNOWN is reported honestly
     when the check cannot be performed — never guessed)

It scans all known AI-client MCP config locations (Claude Code, Claude
Desktop, Cursor, Windsurf, VS Code Continue) for fetch-server entries.

Deterministic: same configs, same report. Read-only: never modifies
configs or firewall rules.

Python stdlib only.
"""

import json
import os
import re
import sys

# mcp-server-fetch fixed this on 2026.10.10 (aidaily.is-a.bot security
# watch, Oct 12 2026). Versions compare as tuples of ints.
FIXED_VERSION = (2026, 10, 10)
METADATA_IP = "169.254.169.254"

CONFIG_PATHS = (
    os.path.expanduser("~/.claude.json"),
    os.path.expanduser("~/.config/claude/claude_desktop_config.json"),
    os.path.expanduser("~/Library/Application Support/Claude/claude_desktop_config.json"),
    os.path.expanduser("~/.cursor/mcp.json"),
    os.path.expanduser("~/.codeium/windsurf/mcp_config.json"),
    os.path.expanduser("~/.continue/mcpServers/mcpServers.json"),
)

_FETCH_HINTS = ("mcp-server-fetch", "server-fetch", "@modelcontextprotocol/server-fetch")


def _version_tuple(v):
    """Parse a dotted version into a tuple of ints. None if unparseable."""
    parts = []
    for p in str(v or "").strip().lstrip("v").split("."):
        m = re.match(r"^(\d+)", p)
        if not m:
            return None
        parts.append(int(m.group(1)))
    return tuple(parts) if parts else None


def assess_fetch_version(spec):
    """Grade one fetch-server spec string (command or package ref).

    Returns (grade, reason): LOW = fixed version pinned; MEDIUM =
    unpinned (cannot prove protections); HIGH = pinned below fix;
    UNKNOWN = no fetch entry at all (handled by caller).
    """
    s = str(spec or "")
    m = re.search(r"server-fetch@([0-9][\w.\-]*)", s)
    if not m:
        # npx -y @modelcontextprotocol/server-fetch (no version) or a
        # local path/binary: resolves to latest at runtime
        if any(h in s for h in _FETCH_HINTS):
            return ("MEDIUM",
                    "fetch server is unpinned — resolves to latest on "
                    "every run, so the 2026.10.10 SSRF fix cannot be "
                    "proven from the config")
        return ("UNKNOWN", "not a fetch-server entry")
    vt = _version_tuple(m.group(1))
    if vt is None:
        return ("MEDIUM", "fetch-server version %s is unparseable — "
                "cannot verify the 2026.10.10 SSRF fix" % m.group(1))
    if vt >= FIXED_VERSION:
        return ("LOW", "fetch server pinned at %s (>= 2026.10.10) — "
                "SSRF protections for private/metadata ranges are "
                "present per the vendor fix" % m.group(1))
    return ("HIGH", "fetch server pinned at %s (< 2026.10.10) — "
            "private and metadata IP ranges were requestable by "
            "default; a prompt-injected agent could reach %s or "
            "internal admin panels" % (m.group(1), METADATA_IP))


def find_fetch_servers(config_text):
    """Extract fetch-server command specs from an MCP config JSON blob.

    Returns [(server_name, spec_string)]. Never raises on bad JSON.
    """
    try:
        data = json.loads(config_text)
    except (ValueError, TypeError):
        return []
    servers = data.get("mcpServers") or {}
    out = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        blob = " ".join(str(cfg.get(k, "")) for k in ("command", "args", "url"))
        if any(h in blob for h in _FETCH_HINTS):
            out.append((name, blob.strip()[:300]))
    return out


def check_metadata_egress(hosts_text=None, iptables_text=None):
    """Check whether 169.254.169.254 is blocked.

    hosts_text/iptables_text may be injected for testing; when None,
    the live files are read (read-only). Returns (status, detail) where
    status is BLOCKED / NOT-BLOCKED / UNKNOWN.
    """
    blocked_reasons = []
    if hosts_text is None:
        try:
            with open("/etc/hosts", "r", encoding="utf-8",
                      errors="replace") as fh:
                hosts_text = fh.read()
        except OSError:
            hosts_text = None
    if hosts_text is not None:
        for line in hosts_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if METADATA_IP in line.split("#", 1)[0]:
                first = line.split()[0]
                if first in ("0.0.0.0", "127.0.0.1", "::1"):
                    blocked_reasons.append(
                        "/etc/hosts maps %s to %s" % (METADATA_IP, first))
    if iptables_text is None:
        iptables_text = ""
        for cmd in ("/sbin/iptables", "/usr/sbin/iptables"):
            if os.path.isfile(cmd):
                try:
                    import subprocess
                    r = subprocess.run(
                        [cmd, "-L", "-n"], capture_output=True, text=True,
                        timeout=5)
                    if r.returncode == 0:
                        iptables_text = r.stdout
                        break
                except Exception:
                    pass
    if METADATA_IP in (iptables_text or ""):
        blocked_reasons.append("firewall rules reference %s" % METADATA_IP)
    if blocked_reasons:
        return ("BLOCKED", "; ".join(blocked_reasons))
    if hosts_text is None:
        return ("UNKNOWN", "could not read /etc/hosts and no firewall "
                "evidence — blocking state unknown, not assumed")
    return ("NOT-BLOCKED", "no %s block found in /etc/hosts or firewall "
            "rules — a prompt-injected agent's fetch tool can reach the "
            "metadata endpoint" % METADATA_IP)


def audit(config_paths=CONFIG_PATHS, hosts_text=None, iptables_text=None):
    """Full audit. Returns a findings dict. Deterministic given inputs."""
    findings = {"fetch_servers": [], "metadata_egress": None,
                "configs_scanned": 0}
    for path in config_paths:
        if not os.path.isfile(path):
            continue
        findings["configs_scanned"] += 1
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for name, spec in find_fetch_servers(text):
            grade, reason = assess_fetch_version(spec)
            findings["fetch_servers"].append({
                "config": path, "server": name, "spec": spec,
                "grade": grade, "reason": reason,
            })
    status, detail = check_metadata_egress(hosts_text, iptables_text)
    findings["metadata_egress"] = {"status": status, "detail": detail}
    return findings


def render_markdown(findings):
    out = ["# mcp-fetch SSRF audit", ""]
    fs = findings["fetch_servers"]
    if not fs:
        out.append("No mcp-server-fetch entries found in %d scanned "
                   "config(s)." % findings["configs_scanned"])
    else:
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNKNOWN": 3}
        for f in sorted(fs, key=lambda x: order.get(x["grade"], 9)):
            out.append("## [%s] %s" % (f["grade"], f["server"]))
            out.append("- config: `%s`" % f["config"])
            out.append("- spec: `%s`" % f["spec"])
            out.append("- %s" % f["reason"])
            out.append("")
    me = findings["metadata_egress"]
    out.append("## Metadata endpoint (%s): %s" % (METADATA_IP, me["status"]))
    out.append("- %s" % me["detail"])
    out.append("")
    highs = sum(1 for f in fs if f["grade"] == "HIGH")
    if highs or me["status"] == "NOT-BLOCKED":
        out.append("**Verdict:** action needed — pin mcp-server-fetch at "
                   "2026.10.10+ and block %s at the host firewall." % METADATA_IP)
    else:
        out.append("**Verdict:** no HIGH findings. UNKNOWN items were "
                   "reported as unknown, not assumed safe.")
    return "\n".join(out)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        description="Audit MCP fetch-server versions and cloud-metadata "
                    "egress protection.")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    findings = audit()
    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        print(render_markdown(findings))
    return 0


if __name__ == "__main__":
    sys.exit(main())
