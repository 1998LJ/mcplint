# mcplint — agent notes

## What this is

Local-first, CI-native security scanner for MCP configs and agent skill files.
13 rules mapped to the OWASP MCP Top 10. Static only — it never executes MCP
servers; no network unless `--online`.

- GitHub: https://github.com/dtduc-git/mcplint
- PyPI: `mcplint-sec` (the command is `mcplint`)
- Install: `uvx mcplint-sec scan`

## Current state (2026-09-13)

- **v0.1.1 released.** Publishing is automated around `release.yml` (trusted
  publishing): bump `src/mcplint/__init__.py`, commit, `git tag vX.Y.Z`, push.
- CI (`.github/workflows/ci.yml`): ruff + pytest + self-scan on fixtures.
- Research dataset: `research/state-of-mcp-configs.md` (1,210 public configs
  from 1,197 repos, 56.5% with findings). Regenerate with
  `uv run python scripts/ecosystem_scan.py --per-query 400 --online`
  (raw per-repo data is gitignored under `research/data/` — do not publish it).
- Blog post: `blog/2026-09-13-state-of-mcp-configs.md`.
- Open PRs: `Puliczek/awesome-mcp-security#325`,
  `AIM-Intelligence/awesome-mcp-security#54`.
- Do not publish announcements or promotional content to external channels
  (Hacker News, Reddit, social media, mailing lists) without explicit user
  approval — keep changes to the repo, its docs and directory listings.

## Layout

- `src/mcplint/` — `models.py`, `discovery.py` (recursive config/skill
  discovery), `parse.py` (JSON/JSONC/TOML), `packages.py` (npm/PyPI refs),
  `checks.py` (check registry via `@check("name")`), `lockfile.py`,
  `aibom.py`, `report/{pretty,sarif}.py`, `rules/` (loader + model),
  `rules_data/*.yaml` (one file per rule).
- Rules are **data (YAML)** + small tested functions in `checks.py`. A rule
  declares `id`, `severity`, `owasp`, `check`, `targets`, `params`.
- `fixtures/vulnerable-repo/` + `fixtures/clean-repo/` — every rule needs
  fixture coverage; the clean repo must stay at zero findings.

## Conventions

- Findings must carry a precise remediation message.
- Severities: `critical > high > medium > low > info`; `--fail-on` default
  `high`. When in doubt about a pattern, rank severity down, not up.
- Version is single-sourced from `src/mcplint/__init__.py`.
- Verify before claiming done:
  `uv sync --all-groups && uv run ruff check . && uv run pytest`

## Next steps

- P1 features: `--connect` sandboxed introspection, optional LLM deep pass
  (BYOK) for tool-description poisoning.
- Grow the rule catalog; keep false-positive rate low — dogfood with
  `uv run mcplint scan --home` and on real repos before shipping rules.
- Watch the two awesome-list PRs; refresh the dataset after a few months.
