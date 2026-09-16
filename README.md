# mcplint

**Local-first, CI-native security scanner for MCP servers.**
OWASP MCP Top 10 rules, a lockfile for rug-pull detection, and an AIBOM export.
It never executes your MCP servers.

[![CI](https://github.com/dtduc-git/mcplint/actions/workflows/ci.yml/badge.svg)](https://github.com/dtduc-git/mcplint/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcplint-sec)](https://pypi.org/project/mcplint-sec/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![M8ven Live Monitored](https://m8ven.ai/badge/mcp/dtduc-git-mcplint-1qvg1q)](https://m8ven.ai/mcp/dtduc-git-mcplint-1qvg1q)

```
uvx mcplint-sec scan
```

> PyPI distribution is `mcplint-sec` (the `mcplint` name collides with an
> existing project); it installs the **`mcplint`** command. With `uvx`, invoke
> it by distribution name: `uvx mcplint-sec …`.

---

## Why

MCP went from a few hundred servers to a 10,000+ server ecosystem — and the
security model did not keep up:

- ~40% of internet-exposed MCP servers have **no authentication** (Censys, 2026)
- A single compromised MCP server reaches a **78% attack success rate** when
  five servers share one agent (arXiv 2601.17549)
- `CVE-2025-6514` in `mcp-remote` (CVSS 9.6) affected a package with 437k+ downloads
- Registries accepted typosquatted MCP servers; tool descriptions are mutable
  after approval ("rug pulls")

Most scanners run on **your machine** and hand your tool descriptions to a
vendor API. mcplint scans the **configs in your repo**, in CI, with nothing
leaving your environment.

## Quickstart

```bash
# scan the current repo
uvx mcplint-sec scan

# also scan user-level client configs and skills
uvx mcplint-sec scan --home

# pin server fingerprints, detect drift in CI
uvx mcplint-sec lock
uvx mcplint-sec lock --check

# CycloneDX AIBOM of every MCP server
uvx mcplint-sec inventory -o aibom.json

# what do the rules mean?
uvx mcplint-sec rules list
uvx mcplint-sec rules explain MCP004
```

Exit code is `1` when a finding at `--fail-on` severity (default `high`)
exists — drop it into CI as-is.

## What it scans

| Input | Examples |
| --- | --- |
| MCP configs | `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `opencode.json[c]`, `.codex/config.toml`, `~/.codeium/windsurf/mcp_config.json`, `~/.gemini/settings.json` |
| Instruction / skill files | `SKILL.md`, `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.windsurfrules`, `.github/copilot-instructions.md`, `.cursor/rules/*.mdc` |

Scans recurse into subdirectories (`node_modules`, virtualenvs and build
outputs are skipped), so monorepos work out of the box.

## Rules

| Rule | Severity | OWASP MCP Top 10 | Checks |
| --- | --- | --- | --- |
| MCP001 | critical | MCP01 Token Mismanagement | hardcoded secrets in env/args/headers |
| MCP002 | medium | MCP01 | unsafe config file permissions |
| MCP003 | medium | MCP04 Supply Chain | unpinned `npx`/`uvx`/`pipx` packages |
| MCP004 | high | MCP04 Supply Chain | typosquat/lookalike package names |
| MCP005 | high | MCP07 Auth | remote endpoint over plain `http://` |
| MCP006 | medium | MCP07 Auth | remote endpoint with no auth material |
| MCP007 | medium | MCP02 Scope Creep | filesystem server scoped to `/`, `$HOME`, ... |
| MCP008 | high | MCP05 Command Execution | shell / command-execution servers |
| MCP009 | high | MCP03 Tool Poisoning | prompt-injection indicators in instructions |
| MCP010 | critical | MCP03 Tool Poisoning | zero-width / bidi unicode (hidden text) |
| MCP011 | medium | MCP03 Tool Poisoning | cross-config server name shadowing |
| MCP012 | high | MCP03 Tool Poisoning | lockfile drift (rug-pull detection) |
| MCP013 | high | MCP04 Supply Chain | pinned packages matching OSV advisories (`--online`) |

Rules are data: plain YAML in [`src/mcplint/rules_data/`](src/mcplint/rules_data).
Bring your own with `--rules-dir ./my-rules`.

## GitHub Actions

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: dtduc-git/mcplint@main
    with:
      fail-on: high
```

Findings show up as annotations and in the repo's code-scanning tab (SARIF).

## Design principles

1. **Never executes your MCP servers.** Scanning is static by default; running
   arbitrary server commands in CI is not acceptable.
2. **Nothing leaves your machine** unless you opt in with `--online` (OSV CVE
   lookups only).
3. **Pin and diff.** `.mcplint.lock.json` fingerprints every server (salted
   hashes for env values) so post-approval changes are visible in `git diff`.
4. **Rules as data.** YAML + a small, tested check engine — contributions do
   not need to touch the scanner core.
5. **Non-goals:** no gateway, no proxy, no runtime traffic monitoring, no SaaS.

## Research

[**State of MCP configs in the wild**](research/state-of-mcp-configs.md) — an
aggregate scan of 1,210 public MCP configs from 1,197 repositories (56.5% have
at least one finding). Methodology and the reproducible script
([`scripts/ecosystem_scan.py`](scripts/ecosystem_scan.py)) are included.

Read the write-up: [We scanned 1,210 MCP configs on GitHub. 56% have a security finding.](blog/2026-09-13-state-of-mcp-configs.md)

## Development

```bash
uv sync --all-groups
uv run pytest
uv run ruff check .
uv run mcplint scan fixtures/vulnerable-repo --fail-on none
```

## License

Apache-2.0
