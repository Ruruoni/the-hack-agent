# D02 (extension) — Traffic Interception, Binary Analysis, Deep Secret Scanning

Three distinct capabilities grouped together because each is a
deeper/more specialized variant of something already covered elsewhere
in the methodology, rather than a new OWASP-style category of its own.

## Traffic interception (`traffic_capture`, mitmproxy)
A deeper variant of A02's "sensitive data in transit" checks --
instead of guessing which calls might be unencrypted or leak tokens,
actually capture what a client sends for a bounded window and read it.

- Use when a mobile app's or SPA's JS-bundle review (A02's basic tier)
  isn't conclusive, or when you need to see real request/response pairs
  rather than inferring from static code.
- `traffic_capture(target='https://app.example-lab.local', duration_seconds=30)`
  -- deliberately short windows (hard-capped at 300s). Read the flow
  summary for: tokens/credentials in URLs or unencrypted headers, API
  calls to unexpected third-party hosts, and any plaintext HTTP mixed
  into an otherwise-HTTPS flow.
- This requires actual traffic to be routed through the proxy during
  the capture window to find anything -- an empty result most often
  means nothing was driving traffic through it, not that the app is
  clean; say so explicitly rather than reporting "no findings" as if it
  were conclusive.

## Binary/firmware analysis (`binary_analysis`, Ghidra headless)
Comes up less often than the web-focused playbooks, but matters for IoT/
embedded/firmware engagements or when a suspicious executable turns up
during an engagement.

- `binary_analysis(path='/local/firmware.bin')` -- headless import +
  default analysis (strings, function identification). This triages a
  binary; it does not replace the judgment a human reverse engineer
  applies in Ghidra's interactive GUI for anything beyond initial
  triage.
- What to look for in the output: embedded credentials/API keys
  (cross-reference with A02/secret-scanning), hardcoded IP addresses or
  URLs (potential C2 or update-server endpoints worth checking against
  scope), and any strings suggesting a known, outdated third-party
  library (cross-reference with A06).
- Never execute the binary to "see what it does" as part of this
  playbook -- that is a fundamentally different, much higher-risk
  activity (dynamic analysis / detonation) requiring an isolated sandbox
  and separate explicit approval, not something this static-analysis
  tool does or implies.

## Deep secret scanning (`deep_secret_scan`, TruffleHog)
A more thorough variant of A02/A05's `secret_scan` (gitleaks) --
broader detector coverage, and `only_verified=True` by default
live-verifies each candidate secret against its actual provider API
before reporting it, cutting false positives sharply.

- Prefer `deep_secret_scan` over plain `secret_scan` when false
  positives from the simpler tool are a problem, or when scanning a
  git repo's *full history* matters (a secret removed in a later
  commit is still exposed in history, and both tools catch this, but
  TruffleHog's verification step tells you definitively whether that
  old secret is still live).
- A verified-live secret is categorically worse than an unverified
  pattern match -- report it as Critical immediately regardless of
  how old the commit is, since "it's an old commit" does not mean the
  credential has been rotated.

## Tools
`traffic_capture` (mitmproxy/mitmdump), `binary_analysis` (Ghidra
headless), `deep_secret_scan` (TruffleHog).

## Reporting notes (b01 cross-reference)
Map each finding to whichever root category it actually represents
(A02 for traffic/secrets findings, A06 for outdated-library findings
from binary analysis) rather than treating "found via a specialized
tool" as its own category -- same principle C04 states for API-fuzzing
findings.
