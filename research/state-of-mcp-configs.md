# State of MCP configs in the wild

_Generated 2026-09-13T03:49:33.421311+00:00 with mcplint 0.1.0._

## Methodology

Public MCP client configs were sampled via the GitHub code search API (queries below, first pages of best-match results), filtered to exact live config filenames (template/sample/backup copies excluded), downloaded from raw.githubusercontent.com, and scanned with the mcplint rule engine. Placeholder credentials ("your-key-here", "dummy", ...) are not counted. All stats are aggregate; no repository is named in this report. Cross-file rules (shadowing, lockfile drift) and file-permission checks are excluded. OSV advisory lookups for pinned packages: enabled.

| Query | Files requested |
| --- | --- |
| `filename:.mcp.json` | 263 |
| `filename:mcp.json path:.cursor` | 342 |
| `filename:mcp.json path:.vscode` | 357 |
| `filename:opencode.json` | 195 |
| `filename:config.toml path:.codex` | 340 |

## Headline

- **56.5%** of configs have at least one finding
- **33.6%** reference at least one unpinned package
- **25.5%** declare no auth material for a remote endpoint
- **4.8%** contain credential material in plain text
- **2.8%** define shell / command-execution servers

## Sample

- Files downloaded and parsed: **1210**
- Repositories: **1197**
- Parse failures / unparseable: 287
- MCP servers referenced: **2013**
- Files with at least one finding: **684** (56.5%)

### Transport mix

| Transport | Servers |
| --- | --- |
| stdio | 1363 |
| http | 622 |
| sse | 28 |

## Findings by rule

| Rule | Files affected | Share of files |
| --- | --- | --- |
| MCP003 | 407 | 33.6% |
| MCP006 | 309 | 25.5% |
| MCP001 | 58 | 4.8% |
| MCP008 | 34 | 2.8% |
| MCP005 | 8 | 0.7% |
| MCP013 | 5 | 0.4% |

## Package pinning

- Third-party package references found: **701** across **227** distinct names

| Package | References | Pinned |
| --- | --- | --- |
| `@playwright/mcp` | 76 | 3 (3.9%) |
| `@upstash/context7-mcp` | 68 | 4 (5.9%) |
| `chrome-devtools-mcp` | 45 | 8 (17.8%) |
| `shadcn` | 41 | 5 (12.2%) |
| `mcp-remote` | 24 | 4 (16.7%) |
| `@modelcontextprotocol/server-github` | 22 | 0 (0.0%) |
| `@modelcontextprotocol/server-sequential-thinking` | 19 | 0 (0.0%) |
| `next-devtools-mcp` | 19 | 1 (5.3%) |
| `git+https://github.com/oraios/serena` | 15 | 6 (40.0%) |
| `@modelcontextprotocol/server-memory` | 14 | 0 (0.0%) |
| `task-master-ai` | 14 | 0 (0.0%) |
| `@supabase/mcp-server-supabase` | 13 | 0 (0.0%) |
| `@modelcontextprotocol/server-filesystem` | 11 | 1 (9.1%) |
| `@angular/cli` | 10 | 2 (20.0%) |
| `@mastra/mcp-docs-server` | 7 | 0 (0.0%) |

## Known vulnerable packages (OSV)

- **5** config files reference a pinned package version with a known advisory; **5** distinct package versions matched.

| Package | Advisory |
| --- | --- |
| `@apify/actors-mcp-server@0.9.10` | GHSA-6gr2-qh89-hxwm, GHSA-jwp7-wg77-3w9v |
| `@playwright/mcp@~0.0.70` | GHSA-6fg3-hvw7-2fwq |
| `@playwright/mcp@~0.0.79` | GHSA-6fg3-hvw7-2fwq |
| `chrome-devtools-mcp@0.21.0` | GHSA-3pvj-jv98-qhjq |
| `chrome-devtools-mcp@0.23.0` | GHSA-3pvj-jv98-qhjq |

## Caveats

- GitHub code search returns best-match results, not a uniform random sample; popularity and recency skew the corpus.
- Configs are point-in-time snapshots; a repo can fix a finding later.
- Heuristic rules trade precision for recall; counts are a lower bound on real risk signals, not a per-repo verdict.
- A remote endpoint can enforce authentication server-side even when the config declares no auth material; MCP006 measures what the config itself discloses.

