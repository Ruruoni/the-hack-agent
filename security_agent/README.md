# security_agent

An authorization-gated, model-agnostic security testing agent, for testing
**external targets you have explicit written authorization to test**,
enforced by `scope.yaml` and `guardrails.py` — not by trusting the model.

## Before you run anything

1. Edit `scope.yaml` at the repo root:
   - Set `authorized: true`, `authorized_by`, `authorization_reference`
     **only** once you have real written permission to test the listed
     targets (your own lab, a bug-bounty program, a signed engagement).
   - List only the domains/CIDRs you're actually authorized for.
   - Leave `allow_exploitation: false` and
     `allow_destructive_actions: false` unless you specifically need
     otherwise, and even then every exploitation attempt is human-approval
     gated regardless.
2. Pick a brain. Model-agnostic by design — set via env vars:
   - Free, local: `AGENT_LLM_PROVIDER=ollama` (default), with
     [Ollama](https://ollama.com) running and a model pulled, e.g.
     `ollama pull qwen2.5:14b`.
   - Free, hosted: `AGENT_LLM_PROVIDER=groq`, `AGENT_LLM_BASE_URL=https://api.groq.com/openai`,
     `AGENT_LLM_MODEL=llama-3.3-70b-versatile`, `AGENT_LLM_API_KEY=<your free Groq key>`.
   - Anthropic (if you want Claude driving the harder planning steps):
     `AGENT_LLM_PROVIDER=anthropic`, `AGENT_LLM_MODEL=claude-sonnet-5-5`,
     `AGENT_LLM_API_KEY=<key>`.
3. Install whichever external tools you want available (all optional — a
   missing binary just makes that one tool refuse with a clear message):
   `nmap`, `subfinder`, `httpx` (projectdiscovery), `nuclei`, `semgrep`,
   `gitleaks`, `ffuf`, `testssl.sh` (or `sslscan`), `sqlmap`.

That's it — no training step, no fine-tuning. The moment `scope.yaml` is
authorized and a model is wired up, the agent already has the full OWASP
Top 10 methodology loaded (see **Built-in OWASP knowledge** below) and
every tool needed to act on it.

## Running

```bash
pip install -r security_agent/requirements.txt
python -m security_agent.cli check-scope

# Free-form objective
python -m security_agent.cli run "Enumerate subdomains of example-lab.local, probe which are alive, and run a safe web vuln scan on each."

# Ready-made OWASP Top 10 assessment, full or one category
python -m security_agent.cli owasp-scan juice.example-lab.local
python -m security_agent.cli owasp-scan juice.example-lab.local --category a03

# See what methodology is loaded
python -m security_agent.cli list-playbooks
```

Every run:
- Refuses outright if `scope.yaml` isn't `authorized: true`.
- Rejects any target not in `allowed_domains`/`allowed_cidrs`.
- Blocks on a human `y/N` prompt for anything scope.yaml lists under
  `require_human_approval_for` (exploitation, credential testing, etc.).
- Writes a full markdown report to `reports/run-<timestamp>.md`.
- Appends every decision (authorized, refused, result) to
  `reports/audit.jsonl`.
- Writes a short note to `knowledge/` that's fed back in as context on the
  next run — the "self-growth" memory.

## Built-in OWASP knowledge

`knowledge/playbooks/` ships with a curated, human-written methodology
covering every OWASP Top 10 (2021) category plus an AI agent/LLM
extension — `00-methodology.md` sets the phase order (scope confirmation
→ passive recon → mapping → vulnerability ID → gated exploitation →
reporting); `a01` through `a11` give basic/intermediate/advanced steps,
example commands, and which tool to use, for that category.
`b01-governance-compliance-mapping.md` adds the defensive/governance
lens on top: how to map every finding to **NIST CSF 2.0**, **ISO/IEC
27001:2022**, **CIS Controls v8**, and **PCI DSS v4.0**, and ground it in
real-world attacker behavior (breach macro-patterns and MITRE ATT&CK
technique IDs) — the reporting template the agent uses for every
finding. `memory.py` loads all of it, in full, into the system prompt
every run (`KnowledgeBase.load_playbooks()`), so a freshly swapped-in
model is already working from this methodology on its very first run —
nothing to fine-tune, nothing to teach it first.

This is separate from the growth notes (next section): the playbooks are
curated and reviewed like code; the growth notes are what the agent
itself writes after each run.

## Tool coverage

| Tool | Category | Covers |
|---|---|---|
| `port_scan` (nmap) | passive_recon | service/version discovery |
| `subdomain_enum` (subfinder) | passive_recon | attack-surface mapping |
| `http_probe` (httpx) | passive_recon | alive hosts, tech fingerprint |
| `tls_scan` (testssl.sh/sslscan) | passive_recon | A02 crypto/TLS config |
| `jwt_analyze` (local) | passive_recon | A02/A07 JWT weaknesses |
| `web_vuln_scan` (nuclei) | active_scanning | A05/A06, broad CVE/misconfig |
| `directory_bruteforce` (ffuf) | active_scanning | A01/A05 hidden paths |
| `http_request` | active_scanning | manual probes: CORS, IDOR, SSRF setup |
| `sql_injection_test` (sqlmap) | active_scanning, or **exploitation** if `dump=True` | A03 injection |
| `ai_agent_redteam` (hackagent) | active_scanning | A11, prompt injection/jailbreak probes against AI agent/LLM targets |
| `k8s_live_scan` (kube-hunter) | active_scanning | C02, live Kubernetes cluster network target |
| `api_fuzz_test` (Schemathesis) | active_scanning | C04, schema-driven API fuzzing |
| `sast_scan` (semgrep) | local | source-level review |
| `secret_scan` (gitleaks) | local | leaked credentials |
| `cloud_posture_scan` (Prowler) | local (credentialed audit, no network target) | C01, AWS/Azure/GCP/K8s misconfig |
| `container_image_scan` (Trivy) | local (read-only image/IaC inspection) | C02, container image & IaC scanning |
| `smart_contract_scan` (Slither) | local (source analysis) | C03, Solidity vulnerability classes |
| `email_harvest` (theHarvester) | passive_recon | D01, emails/subdomains from public sources |
| `username_osint` (Sherlock) | local (subject-scoped, not a network host) | D01, username enumeration across platforms |
| `crypto_toolkit` (local) | local (pure computation, no target) | F01, base64/hex/binary/Caesar/ROT13/Morse/XOR/hash-ID |
| `traffic_capture` (mitmproxy) | active_scanning | D02, bounded reverse-proxy traffic capture |
| `binary_analysis` (Ghidra headless) | local (binary/firmware triage) | D02, static triage of a local binary |
| `deep_secret_scan` (TruffleHog) | local (source/history analysis) | D02, secret scanning with live verification |
| `fast_port_scan` (RustScan) | passive_recon | E01, full-range port coverage |
| `packet_capture` (tcpdump) | passive_recon | E01, bounded capture on a local interface |
| `credential_test` (Hydra) | **exploitation**, always, regardless of scope.yaml | E01, <=25 candidates vs. ONE named account |
| `hash_crack` (Hashcat) | **exploitation**, always, regardless of scope.yaml | E01, offline crack of an already-extracted hash file |
| `active_directory_recon` (BloodHound collector) | active_scanning | E01, read-only AD relationship mapping |
| `phishing_simulation_launch` (GoPhish) | **exploitation**, always, regardless of scope.yaml | E01, launches a pre-built/reviewed campaign only |
| `propose_fix` | passive_recon (drafts only, touches nothing) | Drafts a reviewable patch/config-snippet for a confirmed finding |
| `apply_fix_to_repo` (git) | **any_write_to_target**, always, regardless of scope.yaml | Applies a drafted fix to a LOCAL repo clone (branch+commit, never pushes) |
| `format_bug_report` | passive_recon (drafts only, touches nothing) | Formats a finding + fix into a standard downloadable report file |
| `submit_bug_report` (email/API) | **external_disclosure**, always, regardless of scope.yaml | Sends a drafted report to a confirmed recipient in scope.yaml's disclosure.allowed_recipients |

All of the above are optional external dependencies — a missing binary
makes that one tool refuse with a clear message, nothing is vendored
into this repo. Sources: `hackagent` (AISecurityLab/hackagent,
Apache-2.0), Prowler (prowler-cloud/prowler, Apache-2.0), Trivy and
kube-hunter (aquasecurity, Apache-2.0), Slither (crytic/slither,
AGPL-3.0), Schemathesis (schemathesis/schemathesis, MIT), theHarvester
(laramies/theHarvester, GPL-3.0), Sherlock (sherlock-project/sherlock,
MIT), mitmproxy (mitmproxy/mitmproxy, MIT), Ghidra
(NationalSecurityAgency/ghidra, Apache-2.0), TruffleHog
(trufflesecurity/trufflehog, AGPL-3.0), RustScan (RustScan/RustScan,
MIT), Hydra (van-hauser/thc-hydra, AGPL-3.0), Hashcat
(hashcat/hashcat, MIT), BloodHound.py (dirkjanm/BloodHound.py, MIT),
GoPhish (gophish/gophish, MIT). See `knowledge/playbooks/a11-*.md`,
`c01-*.md` through `c04-*.md`, `d01-*.md`/`d02-*.md`, `e01-*.md`, and `f01-*.md`
for how each is used.

### Deliberately not wrapped

Three tools here (`credential_test`, `hash_crack`,
`phishing_simulation_launch`) carry a hardcoded `exploitation` action
category that cannot be removed by editing scope.yaml — they always
block on explicit human approval, named precisely, every single call.
That is this repo's actual answer to "ask for permission before using
powerful tools": the gate already exists (`require_human_approval_for`
+ `guardrails.py`'s `ApprovalGate`), and every new tool added here
either uses it or, for `credential_test`/`hash_crack`/
`phishing_simulation_launch` specifically, cannot bypass it at all.

What a permission prompt does *not* fix is a tool whose single
approved action can itself cascade into effectively unbounded further
compromise — that's a different problem than "did a human say yes."
These remain out of the tool registry regardless of gating:

- **Full exploitation frameworks** (Metasploit, Commix, RouterSploit):
  built to go from "confirm a bug" to "I have a shell" and keep going.
  This repo's design is "confirm with one minimal, stop-here action"
  (see how `sql_injection_test(dump=True)` only ever pulls one row) —
  a framework's entire purpose is to not stop there.
- **Post-compromise lateral-movement/credential-dumping toolkits**
  (Mimikatz, Rubeus, Certipy, NetExec/CrackMapExec, Impacket's
  lateral-movement scripts such as secretsdump.py/psexec.py, Pacu):
  these assume an existing foothold and use it to escalate to full
  domain or cloud-account control. One approval here doesn't approve
  "check one thing," it approves "now own the environment" — `e01`'s
  playbook makes the same point about `active_directory_recon`
  specifically: map the attack path, never walk it.
- **BeEF**: requires hooking a real, unwitting person's browser —
  running exploit code against an actual human, not infrastructure.
- **Shared-medium/broadcast techniques** (Ettercap, Bettercap,
  wireless-attack suites — Aircrack-ng, Wifite, Reaver, Kismet,
  hcxdumptool): ARP spoofing and wireless deauth can affect devices
  beyond the named target by how the medium works, and no radio
  hardware exists in a sandboxed runner to use these anyway.
- **Masscan**: its own well-documented failure mode is accidentally
  flooding a network at high packet rates; `fast_port_scan` (RustScan)
  covers the "faster than nmap" need without that risk profile.
- **DDoS and phishing-*attack*** tooling (as distinct from
  `phishing_simulation_launch`'s pre-reviewed-campaign-only design):
  not built here under any approval framing — this is a hard line,
  not a configurable one.
- **"Menu" aggregator repos** that bundle dozens of tools under one
  installer (`Z4nzu/hackingtool`, `Manisso/fsociety` — both cloned and
  reviewed, not just skipped on name; the former explicitly catalogs
  DDoS and phishing-attack categories, the latter bundles brute-forcers
  and post-exploitation tooling alongside legitimate recon tools).

If you want one of these wrapped for a specific, narrow, well-bounded
use case, that's a deliberate design decision to make explicitly —
scope the action the way `credential_test` scopes Hydra (one account,
25 candidates, hardcoded exploitation gate) — not a default to add by
widening an existing tool's generality.

## Fix generation and reporting (the actual point, for most real-world use)

Finding a vulnerability isn't the deliverable by itself. Two drafting
tools run automatically (the system prompt in `loop.py` calls for both)
right after every finding with a known, demonstrable fix:

1. **`propose_fix`** drafts a reviewable patch or config/IaC snippet to
   `reports/fixes/*.md` — root cause, the fix itself, and how to verify
   it.
2. **`format_bug_report`** turns the finding plus that fix draft into a
   standard, downloadable report file (`reports/bug_reports/*.md`,
   HackerOne-style: Summary, Steps to Reproduce, Impact, Evidence,
   Suggested Fix).

Neither needs approval, because neither touches anything — they only
write markdown files, the same way the run report itself gets written
without a prompt. This pair is this agent's actual output for most
real-world use: a finding, reported properly, with a concrete fix
recommendation attached, ready to relay.

Two further tools exist for the separate, later moments after that —
never a default next step the agent takes on its own:

- **`apply_fix_to_repo`** actually branches/applies/commits a fix on a
  LOCAL git repo clone. Only for when a system owner has separately
  engaged the operator to implement a fix on a repo they've given
  access to. Locked behind the unconditional `any_write_to_target`
  approval gate. Never pushes to a remote or opens a PR itself — that
  stays an explicit human action even once applied locally.
- **`submit_bug_report`** actually sends a drafted report — by email or
  via a bug-bounty platform's API — to the organization's own
  disclosure channel. Only for when the human operator has explicitly
  asked for that specific send. Locked behind the unconditional
  `external_disclosure` approval gate, and the recipient is checked
  against `scope.yaml`'s `disclosure.allowed_recipients` *before* the
  approval prompt even fires — deliberately separate from
  `targets.allowed_domains`, since the organization's real disclosure
  contact is very often a different domain than whatever was actually
  tested (a HackerOne/Bugcrowd-hosted inbox, a parent company's
  security@ address). An explicit human instruction to send still can't
  reach a recipient that hasn't been separately confirmed and listed
  there — that confirmation (you've checked their security.txt or
  bounty-program page) is what the list represents, not a limitation on
  top of it.

By default, the person running this agent relays the drafted report
themselves through whatever channel their engagement actually uses
(a bug-bounty platform, a direct email, a client relationship) — that
is still the expected path; `submit_bug_report` exists for when they
specifically want the agent to send it instead, not as a replacement
for that default.

## Self-growth, safely

The agent doesn't rewrite its own code unsupervised. Growth happens two ways:

1. **Knowledge growth** — `knowledge/*.md` notes accumulate automatically
   and get reviewed/pruned like any other file in PRs.
2. **Capability growth** — adding a new tool in `security_agent/tools/`,
   adjusting the prompt in `loop.py`, or loosening `scope.yaml` is a normal
   pull request. Two CI gates run on it: `.github/workflows/tests.yml`
   (the `tests/` suite — fast, no GPU/LLM/network needed, runs on every
   push) and `.github/workflows/security-agent-eval.yml`
   (`evals/run_eval.py` against your own lab targets — needs a live model,
   only runs on agent-touching PRs). `CODEOWNERS` requires your review on
   `scope.yaml`, `guardrails.py`, and its test file specifically, so the
   agent's own proposed changes can never loosen its safety boundary (or
   the tests that would catch a regression there) without a human
   approving it.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

127 tests covering `guardrails.py` (scope/budget/approval enforcement —
the single most safety-critical file here), every tool's guardrail
integration and category-escalation logic, `memory.py`'s playbook/
growth-note loading, the CLI, and the full agent loop against a scripted
fake provider. No GPU, API key, or network access needed — these are
pure logic tests, separate from `evals/` (which needs a live model and
real lab targets).

## Extending

Add a new tool by subclassing `security_agent.tools.base.Tool`, giving it
an `action_category` (`passive_recon` / `active_scanning` / `exploitation`),
and registering it in `security_agent/tools/__init__.py`. Every tool call
still goes through `Guardrails.authorize_tool_call()` — there's no path
that skips it.
