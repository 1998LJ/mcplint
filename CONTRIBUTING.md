# Contributing to mcplint

Thanks for helping secure the MCP ecosystem.

## Development setup

```bash
uv sync --all-groups
uv run pytest
uv run ruff check . --fix
uv run mcplint scan fixtures/vulnerable-repo --fail-on none
```

## Adding a rule

Rules are data (YAML); checks are small, tested Python functions.

1. Add a YAML file in `src/mcplint/rules_data/` — see existing rules for shape.
   Every rule declares `id`, `title`, `severity`, `owasp`, `check`, and
   `targets` (`config` and/or `instructions`).
2. If your rule needs new logic, add a function in `src/mcplint/checks.py` and
   register it with `@check("your_check_name")`. Complex checks should be
   configurable through `params` in the YAML.
3. Add fixtures and tests:
   - a positive fixture under `fixtures/vulnerable-repo/` (or a new fixture dir)
   - a negative case in `fixtures/clean-repo/` or a focused unit test
4. Run `uv run pytest` and `uv run ruff check .`.

## Rule quality bar

- No finding without a precise remediation message.
- Prefer deterministic checks; use `--online` gating for anything network-bound.
- Never execute MCP server commands. Static analysis only.
- Keep false positives low: when in doubt, rank severity down, not up.

## Reporting bugs

Open an issue with: mcplint version, the config snippet (redact secrets), and
the expected vs actual finding.

## Security

Do not open public issues for vulnerabilities in mcplint itself — see
[SECURITY.md](SECURITY.md).
