# pretest

Automated pre-pentest self-assessment for web systems. Point it at a host, get
back everything a pentester would find in their first hour — so the paid test
starts at authorisation, business logic and attack chains instead of a public
`/.env` and missing headers.

**This is not a penetration test.** It is a coverage check. It cannot find IDOR,
business-logic flaws, or any injection that lives in your application's own
parameters.

Works against any web system reachable over HTTP(S) — no configuration, no
agent, no account.

## Install

No build step, no dependencies to install. Needs `python3` (3.9+) and `openssl`.

```bash
# one-liner
curl -fsSL https://github.com/alexwest1981/pretest/releases/latest/download/install.sh | bash

# or just take the single file
curl -fsSL https://github.com/alexwest1981/pretest/releases/latest/download/pretest.py -o pretest
chmod +x pretest

# or from source
git clone https://github.com/alexwest1981/pretest && cd pretest && ./pretest.py --self-test
```

Verify the download if you care (a security tool you fetched and are about to run
deserves it):

```bash
curl -fsSL https://github.com/alexwest1981/pretest/releases/latest/download/pretest.py.sha256 | sha256sum -c -
```

## Run it against a system

```bash
./pretest --url https://example.com
./pretest --url https://example.com --domain example.com --repo ~/code/app
./pretest --url https://example.com --fail-on high      # CI gate, exit 1
./pretest --url https://example.com --json report.json  # machine-readable
./pretest --self-test                                   # verify the tool itself
```

A system behind a login is just a header away:

```bash
./pretest --url https://app.example.com -H "Cookie: session=…" -H "Authorization: Bearer …"
```

Third-party host you do not own? Keep it polite and skip the active parts:

```bash
./pretest --url https://example.com --no-dns --no-portscan
```

## Command surface

| Flag | Meaning |
|---|---|
| `--url URL` | Base URL. Required unless `--self-test`. |
| `--domain DOMAIN` | Domain for DNS/e-mail checks (default: hostname from `--url`). |
| `--repo PATH` | Source tree to scan for secrets and dependency vulnerabilities. |
| `--json FILE` | Write the report as JSON. |
| `--no-portscan` | Skip the TCP port check. |
| `--no-dns` | Skip DNS/e-mail checks (also skips the crt.sh lookup). |
| `--delay SECONDS` | Pause between HTTP requests, default `0.2`. |
| `-H`, `--header "Name: value"` | Extra header on every request. Repeatable. |
| `--fail-on LEVEL` | Exit 1 when a finding at this level or worse exists. |
| `--self-test` | Run the built-in test against a local fixture server. |
| `--version` | Print version. |

## What it checks

| Area | Examples |
|---|---|
| artefacts | `/.git/config`, `/.env`, `db.sql`, `backup.zip`, Spring actuator, Go pprof, Laravel Telescope, source maps, swagger/openapi, GraphQL, robots.txt leaks |
| transport | HTTP→HTTPS redirect, HSTS, certificate expiry/chain/SAN, TLS 1.0/1.1, negotiated protocol |
| headers | CSP, frame-ancestors, nosniff, Referrer-Policy, Permissions-Policy, version disclosure |
| cookies | Secure, HttpOnly, SameSite, `__Host-` prefix |
| CORS | Origin reflection with and without credentials, `*` + credentials |
| DNS & e-mail | SPF, DMARC, DKIM selectors, CAA, subdomains via crt.sh, dangling CNAME (takeover) |
| ports | database/cache/dev ports, unauthenticated Docker API |
| source | secrets in files, `.gitignore` gaps, `npm audit`/`pip-audit`/`cargo audit`/`composer audit` when installed |

Anything it could not check is reported as an `info` finding. It never goes quiet:
silence would read as "clean".

## What it cannot check

Copy this list into your pentest scope as required test areas.

- Authorisation and IDOR — swapping an id, reading someone else's data, role escalation
- Business logic — skipping a payment step, negative amounts, race conditions, double spend
- Authentication and sessions — token lifetime, fixation, MFA bypass, password reset
- Injections that need application context — SQLi/NoSQL/SSTI/XXE/SSRF in your own parameters
- File upload, deserialisation, template injection
- Chains: low + low = admin
- The defender's side — is an attack logged and alerted?

## Requirements and limits

- **Linux and macOS** are what it is developed and tested on. Windows is untested.
- TLS checks shell out to `openssl s_client`. A modern OpenSSL build has TLS 1.0/1.1
  compiled out, in which case those versions are reported as *untested*, not as
  unsupported. Use `testssl.sh` when it matters.
- The port check covers 20 common ports, not a full scan. If the hostname sits behind
  a CDN the open ports belong to the CDN edge, and the finding says so.
- Exposed-file detection compares each probe against a random-path baseline, which
  handles single-page apps answering `200` to everything. A clever soft-404 can still
  fool it.
- **Report text is Swedish**; every finding carries a stable English `id` in the JSON,
  so grepping and CI gates do not depend on the prose.
- No severity score. Counts per level, comparable between runs — that is the metric.

## Network behaviour and privacy

No telemetry, no config files, no state — the only thing it writes is the file you
name with `--json`. It makes outbound requests to:

- the target itself (GET/HEAD, plus TCP connects for the port check)
- `cloudflare-dns.com` for DNS lookups (DoH), and `crt.sh` for certificate transparency

Use `--no-dns` to skip the last two entirely.

## Legal

Run it only against systems you own or have written permission to test. The tool
prints that reminder before every scan; an unauthorised scan is a crime in most
jurisdictions (in Sweden, 4 kap. 9 c § brottsbalken).

## Licence

MIT — see [LICENSE](LICENSE). A fork carries its own name.

Copyright (c) 2026 Alex West
