# A08:2021 — Software and Data Integrity Failures

## What it is
Code or data trusted without verifying integrity — insecure
deserialization, unsigned/unverified auto-updates, CI/CD pipeline
tampering, untrusted plugins/dependencies pulled without checksum
verification.

## Basic
- Check for Subresource Integrity (`integrity=` attribute) on any
  third-party script tags loaded from a CDN — its absence means a
  compromised CDN/library could inject arbitrary JS with no detection.
- Check whether auto-update or plugin-install mechanisms verify a
  signature/checksum, or just fetch-and-run.
- `secret_scan` / `sast_scan` on CI/CD config files (`.github/workflows`,
  `Jenkinsfile`, `.gitlab-ci.yml`) if source is available, for secrets
  that would let an attacker tamper with the build pipeline.

## Intermediate
- Insecure deserialization: look for endpoints that accept serialized
  objects (Java `ObjectInputStream`, PHP `unserialize()`, Python `pickle`,
  .NET `BinaryFormatter`) — these are high-value, high-risk findings even
  before confirming exploitability, since confirming usually requires
  code execution.
- If a serialized-object input is found, flag it as a finding with the
  endpoint/parameter and the apparent format, and treat any attempt to
  confirm it with a crafted payload as **exploitation** (approval-gated,
  same as A03's command injection) — don't craft a gadget chain without
  explicit approval.

## Advanced (approval-gated)
- Confirming insecure deserialization typically means achieving some
  code execution — follow A03's command-injection approval path and PoC
  discipline (one harmless, observable command, nothing persistent).

## Tools
`secret_scan`, `sast_scan`, `http_probe`, manual review of client-loaded
third-party resources.

## Remediation to report
Add SRI/signature verification to anything auto-fetched or auto-run,
avoid native deserialization of untrusted input entirely (use JSON with
schema validation instead), and sign/verify CI/CD artifacts end to end.
