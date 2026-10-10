# A05:2021 — Security Misconfiguration

## What it is
Insecure defaults, incomplete configuration, open cloud storage, verbose
error messages, unnecessary features enabled.

## Basic
- `web_vuln_scan` (nuclei tags: `misconfig`, `exposure`, `default-logins`,
  `exposed-panels`) — this category is nuclei's strongest coverage area,
  run it broadly first.
- Check HTTP response headers: missing `X-Content-Type-Options`,
  `X-Frame-Options`/`frame-ancestors`, `Content-Security-Policy`,
  `Referrer-Policy`. Not all are critical alone, but their absence
  compounds with other findings (e.g. no CSP makes any XSS worse).
- Check for verbose error pages (stack traces, framework version banners,
  internal file paths) by sending a malformed request and reading the
  response (`http_request` with a deliberately broken parameter).
- Check for directory listing enabled (`directory_bruteforce` plus
  manually visiting a directory path with no index file).
- `ip_geolocation` on each in-scope host's IP: if the organization has
  stated data-residency requirements (e.g. "EU customer data stays in
  the EU") and the registered hosting location doesn't match, that's
  a finding worth raising even though it's not a traditional
  vulnerability -- cross-reference with PCI DSS/GDPR scope if
  applicable rather than treating it as purely informational.

## Intermediate
- Default credentials on any discovered admin panel, DB admin UI
  (phpMyAdmin, Adminer), or management interface — try only well-known
  defaults (`admin/admin`, `admin/password`) a handful of times, never a
  brute-force loop (that's credential testing, a separate gated
  category).
- Cloud storage: if the app references S3/GCS/Azure Blob URLs, check
  bucket/container listing permissions
  (`curl https://<bucket>.s3.amazonaws.com/`) for public read/write.
- Check for exposed `.git/`, `.env`, `docker-compose.yml`, backup
  (`.bak`, `.old`, `~`) files via `directory_bruteforce` with a
  config-file-focused wordlist.
- Outdated/unpatched software versions identified via `http_probe`'s
  tech-detect — cross-reference with `vulnerable_components` playbook.

## Advanced (approval-gated)
- If a misconfiguration grants write access (an open bucket accepting
  uploads, an admin panel with default creds), confirm with a single,
  reversible action (upload one harmless marker file you then remove, or
  log in once and log back out) rather than using the access further.

## Tools
`web_vuln_scan`, `directory_bruteforce`, `http_probe`, `http_request`.

## Remediation to report
Harden defaults before deployment (disable directory listing, remove
default accounts, generic error pages in production), set standard
security headers, lock down cloud storage permissions, and automate
config review so this doesn't regress silently.
