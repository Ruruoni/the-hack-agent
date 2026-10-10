# B01 — Governance & Compliance Framework Mapping

The `a01`–`a11` playbooks are offensive/technical: how to find a given
class of vulnerability. This one is the defensive/governance layer on
top — once a finding exists, map it to the frameworks an organization is
actually measured against, and to the real-world attacker behavior that
makes it matter. Use this when writing the final report, and whenever the
objective is a posture/compliance review rather than (or in addition to)
active testing.

## The four frameworks, and when each one is the right lens

| Framework | Lens | Use it when the question is... |
|---|---|---|
| **NIST CSF 2.0** | Strategic risk management | "How mature is the organization's overall security program?" |
| **ISO/IEC 27001:2022** | Formal ISMS / audit | "Would this pass a certification audit? Is it documented?" |
| **CIS Controls v8** | Tactical hardening | "What's the prioritized, concrete technical fix?" |
| **PCI DSS v4.0** | Payment-data scope | "Does this touch cardholder data or the CDE?" |

A single finding usually gets mapped to more than one.

### NIST CSF 2.0 — six functions
`GV` Govern (risk strategy, roles, policy) · `ID` Identify (asset
inventory, risk assessment) · `PR` Protect (access control, data
security, awareness training, platform/infra hardening) · `DE` Detect
(continuous monitoring, anomaly detection) · `RS` Respond (incident
response execution, communication) · `RC` Recover (recovery planning,
improvements post-incident).

When mapping a finding, name the function it falls under and which
category inside it (e.g. a missing MFA finding → `PR.AA` — Identity
Management, Authentication, and Access Control).

### ISO/IEC 27001:2022 — Annex A themes
`A.5` Organizational controls (policies, roles, supplier relationships,
incident management process) · `A.6` People controls (screening, training,
disciplinary process, remote working) · `A.7` Physical controls (secure
areas, equipment, clear desk/screen) · `A.8` Technological controls
(access control, cryptography, logging, secure development, vulnerability
management — most technical findings land here).

Report whether a finding also implies a *documentation/process* gap (no
policy covers it) vs. purely a technical gap (the policy exists, the
control failed) — that distinction is what an ISO auditor actually cares
about.

### CIS Controls v8 — 18 controls, by Implementation Group
IG1 (basic hygiene, every org): CIS 1 (Asset Inventory), 2 (Software
Inventory), 3 (Data Protection), 4 (Secure Configuration), 5 (Account
Management), 6 (Access Control Management), 7 (Vulnerability Management,
basic), 10 (Malware Defenses), 14 (Security Awareness).
IG2 (mid-market, adds): 8 (Audit Log Management), 9 (Email/Browser
Protections), 11 (Data Recovery), 12 (Network Infrastructure
Management), 13 (Network Monitoring/Defense), 15 (Service Provider
Management), 16 (Application Security), 17 (Incident Response
Management).
IG3 (enterprise): 18 (Penetration Testing) plus deeper implementation of
all the above.

Map each technical finding to the specific control number and note which
IG it belongs to — this is what tells a reader "fix this first" (low IG
number = more foundational).

### PCI DSS v4.0 — 12 requirements
Only in scope if the target stores, processes, or transmits Cardholder
Data (CHD) or touches the Cardholder Data Environment (CDE) — check this
before applying it.
1–2: Network security controls, secure configurations. 3–4: Protect
stored account data, protect data in transit (encryption). 5–6: Anti-malware,
secure systems/software (this is where most app-layer findings from
`a01`-`a11` land). 7–9: Restrict access by business need-to-know, strong
authentication **including MFA**, restrict physical access. 10: Log and
monitor all access. 11: Regularly test security (this agent's own
scanning activity lives here, and CIS 18/pentesting). 12: Organizational
policy and risk management.

Flag any finding that exposes CHD, weakens CDE segmentation, or lacks
MFA on CDE access as **PCI DSS-relevant** explicitly in the report, since
these can trigger compliance (not just security) consequences.

## Threat-informed mapping

Ground every finding in what attackers actually do, not just what the
frameworks say to prevent, using two layers:

### Macro pattern (industry breach-pattern taxonomy, e.g. Verizon DBIR)
- **System Intrusion** — multi-stage malware/ransomware/extortion; usually
  follows initial access via phishing or an exploited vulnerability.
- **Social Engineering** — phishing, pretexting, business email
  compromise; targets people, not systems.
- **Basic Web Application Attacks** — opportunistic exploitation of
  internet-facing app flaws (maps directly to `a01`-`a10`).
- **Software / Edge Vulnerability Exploitation** — unpatched
  internet-facing software, known-CVE or zero-day exploitation (`a06`).
- **Identity Theft / Credential Abuse** — credential stuffing, password
  spraying, session hijacking, infostealer malware (`a07`).
- **Miscellaneous Errors** — misconfiguration, misdelivery, disposal
  errors — often what `a05` findings actually represent.
- **Privilege Misuse** — insider abuse of legitimate access.
- **Denial of Service** — availability attacks (this agent never
  performs these; report the *exposure*, not a tested DoS).
- **Lost and Stolen Assets** — physical device loss/theft.

Classify each finding into whichever pattern it would most plausibly
fuel if actually exploited, in one short clause.

### Granular: MITRE ATT&CK + kill chain
For each finding, name the ATT&CK tactic(s)/technique ID(s) it would
enable (e.g. an exposed `.env` file with cloud keys → `TA0001 Initial
Access` via `T1552.001 Unsecured Credentials: Credentials in Files`),
and where it sits on the kill chain (Reconnaissance → Weaponization →
Delivery → Exploitation → Installation → Command & Control → Actions on
Objectives). This is what turns "we found X" into "X is how an attacker
would actually get from the internet to your data."

## Reporting template (apply to every finding)

```
Title:            <short description>
OWASP/category:   <a01-a11 reference, if applicable>
Evidence:         <what was observed>
Severity:         Critical / High / Medium / Low / Info
Breach pattern:   <macro pattern>
ATT&CK:           <tactic/technique ID(s)>
NIST CSF 2.0:     <function.category>
ISO 27001:2022:   <Annex A clause>
CIS Control v8:   <control # + IG>
PCI DSS v4.0:     <requirement #, or "not applicable - no CHD/CDE in scope">
Remediation:      <concrete fix>
Fix draft:        <path to the propose_fix output for this finding, if one was drafted>
Bug report:       <path to the format_bug_report output for this finding, if one was drafted>
```

For any finding with a known, demonstrable fix: call `propose_fix` (see
`security_agent/tools/remediation.py`) right after reporting it, then
`format_bug_report` (see `security_agent/tools/bug_report.py`) to turn
the finding plus that fix into a standard, downloadable report file.
Both only draft reviewable files — neither touches the target or sends
anything anywhere, so neither needs approval. This pair is the actual
point of the report for most real-world use (e.g. bug bounty work): a
properly-formatted finding with a concrete, ready-to-relay fix
recommendation attached, which the person running this agent passes to
the system owner themselves through whatever channel their engagement
uses.

Two further actions exist for later, separate moments, and neither is
ever a default next step after drafting: `apply_fix_to_repo` applies a
fix to a local repo clone, only once a system owner has actually
engaged the operator to implement it there; `submit_bug_report` sends
the drafted report by email or API to the organization's own
disclosure channel, only when the human operator has explicitly asked
for that specific send. Both are always approval-gated, unconditionally,
regardless of scope.yaml.

## Hard limit
This playbook is for classification and reporting — it never authorizes
testing anything. Every finding it maps to a framework still had to be
produced by a tool call that `guardrails.py` already authorized against
`scope.yaml`; this file adds no new permission of its own.
