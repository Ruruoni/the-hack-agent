# A01:2021 — Broken Access Control

## What it is
Users acting outside their intended permissions: viewing/editing other
users' data, accessing admin functionality, or bypassing access checks via
URL/parameter manipulation.

## Basic
- Map every role the app has (anonymous, user, admin, etc.) and the
  endpoints each role should/shouldn't reach.
- Check for admin/debug paths exposed to anonymous users:
  `/admin`, `/debug`, `/actuator`, `/console`, `/.well-known/`,
  via `directory_bruteforce` and `web_vuln_scan` (nuclei `exposed-panels`
  tag).
- Check HTTP methods: does `OPTIONS`/`PUT`/`DELETE` work where only `GET`
  should? (`curl -X OPTIONS <url>` via `http_request` tool.)

## Intermediate — IDOR (Insecure Direct Object Reference)
- Authenticate as two low-privilege test accounts (use only accounts you
  created for this engagement — never real user credentials).
- Take an endpoint like `GET /api/orders/1042` as user A; replay it with
  user A's session but a different `id` (user B's). Access granted where
  it should be denied = IDOR.
- Try the same across HTTP verbs and both numeric and UUID/opaque IDs —
  opaque IDs reduce but don't eliminate risk if they're guessable or
  leaked elsewhere (e.g. in another response).
- Check client-side-only authorization: does the UI hide the admin button
  but the API still accept the admin request from a normal account?

## Intermediate — Forced browsing / path traversal
- `directory_bruteforce` with a sensitive-paths wordlist for backup files,
  `.git/`, `.env`, old API versions (`/api/v1/` vs `/api/v2/` — the old
  one often has weaker checks).
- Test `../` traversal in any parameter that looks like a filename or
  path (`?file=report.pdf` → `?file=../../etc/passwd`), but only against
  the lab/target explicitly in scope, and stop at evidence of traversal
  (a file listing or a known marker file) rather than pulling arbitrary
  files.

## Advanced (approval-gated)
- Privilege escalation chain: combine a minor info leak (e.g. an admin
  user ID visible in a public API response) with an IDOR to perform one
  action as that admin, confirming impact with a single, reversible PoC
  (e.g. reading one admin-only field) — not a destructive action.
- CORS misconfiguration enabling cross-origin credentialed reads:
  `curl -H "Origin: https://evil.example" -I <url>` and check if
  `Access-Control-Allow-Origin` reflects arbitrary origins alongside
  `Access-Control-Allow-Credentials: true`.

## Tools
`directory_bruteforce`, `http_probe`, `web_vuln_scan` (tags:
`exposed-panels`, `misconfig`, `default-logins`), manual `http_request`
for verb/IDOR testing.

## Remediation to report
Server-side authorization checks on every request (never trust the
client), deny-by-default access control, indirect/opaque object
references plus an ownership check, and CORS allow-lists instead of
reflecting `Origin`.
