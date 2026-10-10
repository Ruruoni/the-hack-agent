# A06:2021 — Vulnerable and Outdated Components

## What it is
Using a library, framework, OS package, or service with a known CVE, or
one that's simply unsupported/unpatched.

## Basic
- `http_probe`'s tech-detect plus HTTP response headers/banners
  (`Server`, `X-Powered-By`) to fingerprint framework/server/CMS and
  version.
- `web_vuln_scan` (nuclei tag: `cve`, `tech`) to match fingerprinted
  versions against known-CVE detection templates.
- If source is available: dependency manifests (`package.json`,
  `requirements.txt`, `pom.xml`, `go.mod`) checked against public
  advisory databases for known-vulnerable pinned versions.

## Intermediate
- `sast_scan` can surface some vulnerable-pattern usage, but the
  authoritative check is a dependency/SCA scanner
  (`pip-audit`/`npm audit`/`osv-scanner` — run these directly against a
  local checkout the same way `sast_scan`/`secret_scan` operate: as a
  local-path action, not a network target).
- Check for end-of-life software: a fingerprinted version that's past its
  vendor's EOL date is a finding even with no specific CVE yet — note the
  product, version, and EOL date in the report.
- Cross-reference exposed admin panels (A05) with their fingerprinted
  version for a direct CVE lookup (e.g. a specific WordPress plugin
  version with a known authenticated or unauthenticated RCE).

## Advanced (approval-gated)
- If a fingerprinted CVE has a known PoC, confirming it is effectively
  category A03 (injection) or A01 (access control) exploitation —
  classify by *what the CVE actually does* and follow that playbook's
  approval gate, don't treat "it has a CVE number" as license to run an
  exploit automatically.

## Tools
`http_probe`, `web_vuln_scan`, `sast_scan`, plus external SCA tools
(`pip-audit`, `npm audit`) run the same local-path way if you add them to
`security_agent/tools/`.

## Remediation to report
Keep an inventory of dependencies and versions, patch on a cadence
(not only when a CVE is announced), remove unused dependencies, and pin
to maintained, supported versions.
