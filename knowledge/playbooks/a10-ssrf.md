# A10:2021 — Server-Side Request Forgery (SSRF)

## What it is
An app fetches a URL supplied (directly or indirectly) by the user, and
an attacker makes it fetch an internal/unintended target instead
(internal admin endpoints, cloud metadata services, localhost).

## Basic
- Enumerate every feature that fetches a URL server-side: webhooks,
  "import from URL", PDF/thumbnail generators, link-preview features,
  avatar-by-URL uploads, server-to-server integrations with a
  user-configurable endpoint.
- For each, test with an in-scope, agent-controlled callback target only
  (e.g. a host you listed in `scope.yaml` specifically for this purpose)
  to confirm the server actually makes the outbound request — never
  point it at a third party's infrastructure you don't control.

## Intermediate
- Test redirect-based SSRF bypass: if the app validates the URL's
  hostname but then follows redirects, host a redirect to an internal
  address on your own in-scope callback host.
- Test alternate representations of "localhost"/internal ranges that
  naive filters miss: `127.0.0.1`, `0.0.0.0`, `[::1]`,
  `0177.0.0.1` (octal), `http://127.1`, or a DNS name you control that
  resolves to `127.0.0.1` — only against the target's own fetch feature,
  never to actually reach something outside the authorized scope.
- Cloud metadata endpoint probing (`http://169.254.169.254/`) is
  extremely high-signal if it succeeds (can leak cloud credentials) —
  treat any successful fetch of it as a **critical** finding and stop;
  do not pursue extracting the credentials it returns without explicit
  approval, since that crosses into live credential exposure.

## Advanced (approval-gated)
- If SSRF reaches an internal admin interface or metadata endpoint,
  confirming impact beyond "the request was made" (e.g. actually reading
  the metadata response body, or reaching a specific internal admin
  action) requires approval — the detection step above (confirming the
  fetch happened) does not, but using what it exposes does.

## Tools
`http_request` (to configure the vulnerable feature's target URL) plus
`web_vuln_scan` (nuclei tag: `ssrf`) for known-vulnerable
software/plugins.

## Remediation to report
Allow-list permitted destination hosts/schemes for any server-side
fetch feature, disable following redirects (or re-validate post-
redirect), block link-local/metadata/internal ranges at the network
layer as well as in application code, and never return the raw fetched
response body to the user unfiltered.
