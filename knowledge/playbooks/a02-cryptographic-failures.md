# A02:2021 — Cryptographic Failures

## What it is
Sensitive data exposed because it wasn't encrypted, was encrypted weakly,
or TLS itself is misconfigured — formerly "Sensitive Data Exposure".

## Basic
- `tls_scan` (testssl.sh/sslscan) against every in-scope host serving
  HTTPS: protocol versions (flag SSLv3/TLS1.0/1.1 as findings), weak
  cipher suites (RC4, 3DES, NULL ciphers), certificate validity/expiry,
  and whether HTTP→HTTPS redirect exists at all.
- Check for `Strict-Transport-Security` header presence and
  `includeSubDomains`/`preload`.
- Check whether sensitive pages (login, account, payment) are reachable
  over plain HTTP at all (`curl -I http://<host>/login`).

## Intermediate
- Look for sensitive data in transit without TLS internally (API calls
  from JS bundles to `http://` endpoints — grep JS responses for
  `http://` API base URLs).
- Check for sensitive data in URLs (session tokens, passwords, API keys
  as query params — these end up in logs/browser history/referrer
  headers). Grep crawled URLs for `token=`, `password=`, `api_key=`.
- `secret_scan` (gitleaks) against any source code in scope for hardcoded
  keys, and check public JS bundles for embedded API keys
  (`grep -E "api[_-]?key|secret|AKIA[0-9A-Z]{16}"` over fetched JS).
- Check password storage indirectly: does a "forgot password" flow ever
  email/display the *original* password? That means it's stored
  reversibly or in plaintext — a strong finding without needing DB access.

## Advanced (approval-gated)
- If a weak signing/encryption scheme is identified (e.g. a JWT signed
  with `alg: none` or a guessable HMAC secret, or ECB-mode encrypted
  tokens showing block-repetition patterns), demonstrate impact with a
  single forged/decrypted token rather than mass-forging or using it
  beyond the one proof.
- Padding-oracle / predictable-IV checks on any custom crypto are high
  effort and easy to misfire into a DoS (repeated requests) — only pursue
  with explicit approval and strict rate limits per `scope.yaml`.

## Tools
`tls_scan`, `http_probe`, `secret_scan`, `jwt_analyze`, manual
`http_request` for header/redirect checks.

## Remediation to report
TLS 1.2+ only with strong cipher suites, HSTS with `preload`, never put
secrets in URLs, hash passwords with bcrypt/argon2 (never store/email
reversible passwords), rotate any secret found hardcoded or leaked.
