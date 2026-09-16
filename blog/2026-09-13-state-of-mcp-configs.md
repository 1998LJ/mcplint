# We scanned 1,210 MCP configs on GitHub. 56% have a security finding.

_2026-09-13 · research_

MCP went from a few hundred servers to a 10,000+ ecosystem in less than two
years. Every one of those servers gets wired into an agent through a config
file — `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `opencode.json`,
`.codex/config.toml` — and those files are now committed to repositories by the
thousands.

We built [mcplint](https://github.com/dtduc-git/mcplint), a local-first scanner
for exactly that surface, and used it to look at what is actually in those
files.

## What we did

We sampled public MCP configs via the GitHub code search API (first pages of
best-match results across five config types), filtered to exact live config
filenames — no `.sample`, `.template` or `.html` copies — downloaded them, and
ran the mcplint rule engine (13 rules mapped to the
[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)) over the result.

**Sample: 1,210 configs from 1,197 repositories, referencing 2,013 MCP servers.**
The full methodology, the aggregate report and the script are in the repo:
[`research/state-of-mcp-configs.md`](../research/state-of-mcp-configs.md) ·
[`scripts/ecosystem_scan.py`](../scripts/ecosystem_scan.py).

## The headline numbers

| Signal | Share of configs |
| --- | --- |
| At least one finding | **56.5%** |
| References an unpinned package | **33.6%** |
| Declares no auth material for a remote endpoint | **25.5%** |
| Contains credential material in plain text | **4.8%** |
| Defines a shell / command-execution server | **2.8%** |
| Uses plain `http://` for a non-loopback endpoint | **0.7%** |

## Everything is unpinned

A third of configs tell `npx` to fetch a package at run time — no version
anywhere:

```json
{ "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"] }
```

The most-referenced packages in the corpus tell the story. `@playwright/mcp`:
76 references, 3.9% pinned. `@upstash/context7-mcp`: 68 references, 5.9% pinned.
`@modelcontextprotocol/server-github`: 22 references, **0% pinned**. The
registry version is whatever the registry serves that day — a compromised or
broken release is picked up on the next agent start, with no review.

And `mcp-remote` — the package behind **CVE-2025-6514** (CVSS 9.6, command
injection, 437k+ downloads) — appears in 24 configs. Only 4 pin it.

## The auth gap is real but nuanced

A quarter of configs point at a remote endpoint with no `Authorization` header
and no token/key environment variable. Some are intentionally public read-only
endpoints (documentation MCPs, for example) — it measures what the config
discloses, not what the server enforces. Still, an unauthenticated MCP endpoint
is the shape of the problem Censys measured when it found ~40% of
internet-exposed MCP servers had no auth at all.

## Real secrets, committed

58 configs contained plain-text credential material: provider tokens
(`GITHUB_PERSONAL_ACCESS_TOKEN`, `FIRECRAWL_API_KEY`), 44-character access
tokens, bearer tokens in headers, and Postgres URLs with embedded passwords.
Placeholder strings like `your-key-here` are excluded from this count — these
are live-looking values in public code.

## Pinned packages can still be vulnerable

mcplint checks pinned packages against OSV. Five configs matched advisories
this week — including a Playwright MCP version with a DNS-rebinding advisory
and a Chrome DevTools MCP version with a symlink-following file write:

| Package | Advisory |
| --- | --- |
| `@playwright/mcp@~0.0.70`, `@playwright/mcp@~0.0.79` | GHSA-6fg3-hvw7-2fwq |
| `chrome-devtools-mcp@0.21.0`, `@0.23.0` | GHSA-3pvj-jv98-qhjq |
| `@apify/actors-mcp-server@0.9.10` | GHSA-6gr2-qh89-hxwm, GHSA-jwp7-wg77-3w9v |

Pinning is a prerequisite for this check — you cannot match an advisory
against "whatever is latest".

## Check your own repo in 30 seconds

```bash
uvx mcplint-sec scan
```

The command is `mcplint` (the PyPI name has a suffix because `mcplint` collides
with an existing project — we practise what we preach about lookalike names).
It is static-only: it never executes your MCP servers, and nothing leaves your
machine unless you pass `--online`.

For CI:

```yaml
- uses: dtduc-git/mcplint@v0.1.2
  with:
    fail-on: high
```

`mcplint lock` pins every server fingerprint into `.mcplint.lock.json`;
`mcplint lock --check` then fails the build when a server definition changes
after approval — the rug-pull detection OWASP recommends for MCP03.

## Caveats

This is a best-match sample, not a uniform random draw; popularity and recency
skew it. Configs are point-in-time snapshots. Heuristic rules trade precision
for recall — treat the numbers as a lower bound on risk signals, not a verdict
on any repository. No repository is named in the dataset; the raw per-repo
results are intentionally not published.

## Run it yourself

The whole pipeline is reproducible:

```bash
git clone https://github.com/dtduc-git/mcplint
cd mcplint
uv sync --all-groups
uv run python scripts/ecosystem_scan.py --per-query 400 --online
```

---

mcplint is Apache-2.0. Rules are YAML; PRs welcome:
https://github.com/dtduc-git/mcplint
