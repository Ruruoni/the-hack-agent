# Testing methodology (read this first)

This file sets how the agent should sequence any engagement, from a
first-contact conversational ask to a full OWASP Top 10 sweep. The
category playbooks in this folder (`a01-...` through `a10-...`) are the
detail for each OWASP Top 10 (2021) category; this file is the ordering
and ground rules that tie them together.

## Phases, in order

1. **Scope confirmation.** Before anything else, confirm the target is in
   `scope.yaml`'s `allowed_domains`/`allowed_cidrs` and that
   `authorized: true`. The agent cannot bypass this — `guardrails.py`
   re-checks every tool call regardless of what the plan says — but the
   plan itself should never propose a step against a target it hasn't
   confirmed is in scope.
2. **Passive recon.** Subdomain enumeration, DNS, HTTP probing/tech
   fingerprinting, TLS/cert inspection, robots.txt/sitemap, exposed
   .git/.env/backup files, Wayback/cert-transparency history. No payloads
   sent, nothing that could alter state. Tools: `subdomain_enum`,
   `http_probe`, `tls_scan`, `port_scan` (service/version only).
3. **Mapping.** Enumerate the attack surface on each live host: endpoints,
   parameters, forms, directories/files (`directory_bruteforce`),
   authentication flows, API surface, technology stack and versions.
4. **Vulnerability identification (active, non-destructive).** Run
   category-specific detection: `web_vuln_scan` (nuclei, safe templates),
   `sql_injection_test` in detect-only mode, `jwt_analyze`, `sast_scan` /
   `secret_scan` if source is available. Match findings against the
   category playbooks below for what each one means and how confident to
   be before reporting it.
5. **Exploitation (gated — do not attempt without explicit approval).**
   Confirming a vulnerability by extracting a single proof-of-concept
   piece of evidence (e.g. one row via `sql_injection_test(dump=True)`,
   one admin-panel screenshot). Every such action is in
   `scope.yaml: require_human_approval_for` and `guardrails.py` will block
   on a human prompt — propose it, don't assume it will be approved, and
   never chain it into further automated action.
6. **Reporting.** For each finding, use `b01-governance-compliance-mapping.md`'s
   template: title, OWASP/category, evidence, severity (CVSS-style
   Critical/High/Medium/Low/Info), breach macro-pattern, MITRE ATT&CK
   tactic/technique, NIST CSF 2.0 function, ISO 27001:2022 Annex A
   clause, CIS Control v8 (+ Implementation Group), PCI DSS v4.0
   requirement (or "not applicable"), and concrete remediation. Write
   this into the run report; `security_agent/memory.py` also keeps a
   short note in `knowledge/` so the same ground isn't re-covered
   blindly next run.

## Basic → advanced, in one sentence per level

- **Basic:** passive recon + default nuclei templates + reading
  responses — "what's exposed and what's obviously misconfigured."
- **Intermediate:** targeted probing per OWASP category (auth flows,
  injection points, access-control boundaries, business logic) using the
  category playbooks, still non-destructive.
- **Advanced:** approval-gated confirmation of exploitability (minimal
  PoC extraction, chaining a handful of findings to show real impact —
  e.g. an IDOR plus a missing auth check), always ending at a single
  proof, never continued exploitation, data exfiltration at scale, or any
  action `scope.yaml` marks disallowed (destructive actions, DoS).

## Hard limits (not suggestions)

- Never attempt denial-of-service, resource exhaustion, or any action
  `rules_of_engagement` marks false.
- Never write/modify data on a target unless `allow_exploitation` is true
  *and* the specific action is human-approved.
- Never pivot from an in-scope host to an out-of-scope one just because
  the first host links to it — re-check scope for every new host found
  during recon before acting on it.
- If a finding would require touching real user data (not synthetic/lab
  data) to confirm, stop and report the hypothesis instead of confirming
  it.
