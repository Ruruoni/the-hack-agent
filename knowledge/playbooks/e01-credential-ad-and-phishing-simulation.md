# E01 (extension) — Credential Attacks, AD Recon, and Phishing Simulation

The highest-stakes category of tooling this agent carries, by design.
Every tool here is deliberately narrower than the underlying technique
could be, and every exploitation-tier action in this file blocks on
explicit human approval — not because scope.yaml happens to list it,
but because `credential_test`, `hash_crack`, and
`phishing_simulation_launch` are *always* in the `exploitation`
category regardless of configuration. Read `security_agent/README.md`'s
"Deliberately not wrapped" section before using anything here — it
explains which adjacent, more powerful tools (Metasploit, Mimikatz,
Rubeus, Certipy, NetExec, Impacket's lateral-movement scripts, Pacu,
BeEF) were deliberately excluded and why a permission prompt alone
doesn't make those safe to wrap, so you understand the boundary this
playbook operates inside.

## Fast/passive recon companions (lower stakes, covered here for completeness)
- `fast_port_scan` (RustScan): full 65535-port coverage when `port_scan`'s
  top-1000 default isn't enough. Same scope check as `port_scan`.
- `packet_capture` (tcpdump): passive capture on a local interface, for
  engagements run inside the client's own network. Takes a clean
  `target` (host/CIDR) that's scope-checked directly — never pass scope
  validation off to a raw BPF filter string.

## Credential testing (`credential_test`, Hydra)
- Hard-capped at 25 candidate passwords against **one named account**
  you already know to be a test account for this engagement — never a
  real user's account, never a broad spray across many accounts.
- Always exploitation-category: propose it, name the exact account and
  password count, and expect (and wait for) an explicit approval prompt
  every single time — approval from an earlier call never carries over.
- If you need to test more than ~25 candidates or more than one
  account, that is a different, larger engagement decision the human
  operator makes explicitly (e.g. by approving multiple separate calls)
  — this tool will not silently exceed its own cap.

## Offline hash cracking (`hash_crack`, Hashcat)
- Operates only on a hash file **already obtained** through a
  separately-approved extraction step (e.g. `sql_injection_test` with
  `dump=True`, itself already approval-gated). This tool never extracts
  anything — it only attempts to crack hashes already sitting in a
  local file.
- Time-boxed (capped at 600s regardless of what's requested). A
  successful crack demonstrates weak password policy — report it as
  such, don't treat "we cracked one password" as license to then test
  that password against other systems without a fresh, separate
  approval for that specific action.

## Active Directory recon (`active_directory_recon`, BloodHound collector)
- Read-only LDAP/SMB enumeration of group memberships, ACLs, and
  sessions — the same kind of read any domain-authenticated user can
  already perform, not an exploit. Still `active_scanning` (not
  `exploitation`) since it's genuinely non-destructive, but queries
  many hosts across the whole domain in one run, so add it to
  scope.yaml's `require_human_approval_for` yourself if you want it
  individually gated beyond the `active_scanning` default.
- What to do with the results: report attack paths found (e.g. "user X
  has an ACL granting GenericAll over a domain admin's object") as
  findings with severity and remediation — do **not** use this
  agent to then walk that path (abusing the ACL, requesting a
  certificate, etc.). That walk is exactly the kind of multi-step
  privilege-escalation chaining this agent's design deliberately stops
  short of; a human decides whether and how to pursue it, likely with
  the dedicated AD tooling this agent does not wrap.

## Phishing-susceptibility simulation (`phishing_simulation_launch`, GoPhish)
This is the responsible substitute for "phishing attack tools" — it
is built to only ever launch a campaign a human has already authored
and reviewed in GoPhish itself.
- This tool never writes phishing email content, subject lines, or
  landing pages — `campaign_id` must reference something that already
  exists in your own GoPhish instance.
- Every recipient email's domain is checked against scope.yaml's
  `allowed_domains` before anything else — a campaign can only reach
  the organization's own people, confirmed in scope, never an
  arbitrary external list, even if the GoPhish instance itself would
  technically allow it.
- Always exploitation-category: expect an explicit approval prompt
  naming the campaign and the recipient count every time.

## Tools
`fast_port_scan` (RustScan), `packet_capture` (tcpdump),
`credential_test` (Hydra), `hash_crack` (Hashcat),
`active_directory_recon` (BloodHound collector),
`phishing_simulation_launch` (GoPhish).

## Reporting notes (b01 cross-reference)
Credential findings: breach pattern Identity Theft/Credential Abuse,
ATT&CK T1110 (Brute Force) or T1555 (Credentials from Password
Stores), NIST CSF 2.0 PR.AA, CIS v8 Control 5/6. AD recon findings:
breach pattern Privilege Misuse (if the path is abusable by an insider)
or System Intrusion (if abusable post-compromise), ATT&CK T1482 Domain
Trust Discovery / T1069 Permission Groups Discovery, CIS v8 Control 6,
NIST CSF 2.0 PR.AA. Phishing-simulation results: report the
click-through/credential-entry rate as a Social Engineering
breach-pattern metric feeding NIST CSF 2.0's PR.AT (Awareness and
Training), not as a vulnerability with a CVSS-style severity — it's a
measurement of human susceptibility, not a technical flaw to patch.
