# Security Policy

## Reporting a vulnerability

Please report vulnerabilities in mcplint privately via GitHub Security
Advisories: <https://github.com/dtduc-git/mcplint/security/advisories/new>

Include: affected version, reproduction steps, and impact. We aim to
acknowledge within 72 hours.

## Scope

In scope: false negatives/positives that materially mislead, rule-engine
bypasses, lockfile weaknesses (e.g. fingerprint collisions), and any path where
mcplint could execute untrusted input.

Out of scope: vulnerabilities in MCP servers mcplint reports on — those belong
with their maintainers.

## Design guarantees

- mcplint never executes MCP server commands during a scan.
- No network calls unless `--online` is passed.
- Env values are stored in the lockfile only as salted hashes.
