# mcp-fetch-ssrf-auditor

**Your agent's fetch tool is an SSRF-shaped hole that inherits your agent's privilege. Audit it.**

On October 10, 2026, security researchers reported that default `mcp-server-fetch` builds before **2026.10.10** could request private and metadata IP ranges unless operators disabled protections manually. A prompt-injected agent with the fetch tool can reach internal admin panels — or the cloud metadata endpoint `169.254.169.254` — and read instance credentials. No exploit required.

`mcp-fetch-ssrf-auditor` answers two deterministic questions:

1. **Which mcp-server-fetch versions are pinned in your AI-client MCP configs?** Pre-2026.10.10 or unpinned (`npx -y ...` with no version) = the SSRF protections cannot be proven from the config.
2. **Does this host block the cloud metadata endpoint?** Checks `/etc/hosts` and firewall rules for a `169.254.169.254` block. `UNKNOWN` is reported honestly when the check can't be performed — never guessed.

It scans all known AI-client MCP config locations (Claude Code, Claude Desktop, Cursor, Windsurf, VS Code Continue). Read-only — never modifies configs or firewall rules.

## What it flags

| Grade | Meaning |
|-------|---------|
| `HIGH` | Fetch server pinned below 2026.10.10 — metadata/private ranges requestable by default |
| `MEDIUM` | Fetch server unpinned — resolves to latest on every run, fix cannot be proven |
| `LOW` | Pinned at 2026.10.10+ — SSRF protections present per the vendor fix |
| `BLOCKED` / `NOT-BLOCKED` / `UNKNOWN` | Metadata-endpoint egress state on this host |

## What it does NOT do

- It does not test whether your agent would actually follow a malicious fetch instruction — that's a red-team pack's job (see ChatBreaker).
- UNKNOWN means unknown, not safe. Verify the firewall yourself.
- It only covers the fetch tool — other MCP servers have their own SSRF surfaces (see our `mcp-provenance-scanner` for provenance, `mcp-autostart-auditor` for runtime inventory).

## Usage

```bash
python3 mcp_fetch_ssrf_auditor.py --json
```

## Install

Zero dependencies — Python 3.8+ stdlib only.

```bash
git clone https://github.com/Iceman2050/mcp-fetch-ssrf-auditor.git
cd mcp-fetch-ssrf-auditor
python3 mcp_fetch_ssrf_auditor.py --help
```

## Built by Ingenious AI

This tool is built and maintained by **Ingenious AI**. Get early access to our AI security platforms:
## Built by Ingenious AI

This tool is built and maintained by **Ingenious AI**. Get early access to our AI security platforms:

- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI


> Built by Ingenious AI
