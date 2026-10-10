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
| `traffic_capture` (mitmproxy) | active_scanning | D02, bounded reverse-proxy traffic capture |
| `binary_analysis` (Ghidra headless) | local (binary/firmware triage) | D02, static triage of a local binary |
| `deep_secret_scan` (TruffleHog) | local (source/history analysis) | D02, secret scanning with live verification |

All of the above are optional external dependencies — a missing binary
makes that one tool refuse with a clear message, nothing is vendored
into this repo. Sources: `hackagent` (AISecurityLab/hackagent,
Apache-2.0), Prowler (prowler-cloud/prowler, Apache-2.0), Trivy and
kube-hunter (aquasecurity, Apache-2.0), Slither (crytic/slither,
AGPL-3.0), Schemathesis (schemathesis/schemathesis, MIT), theHarvester
(laramies/theHarvester, GPL-3.0), Sherlock (sherlock-project/sherlock,
MIT), mitmproxy (mitmproxy/mitmproxy, MIT), Ghidra
(NationalSecurityAgency/ghidra, Apache-2.0), TruffleHog
(trufflesecurity/trufflehog, AGPL-3.0). See
`knowledge/playbooks/a11-*.md`, `c01-*.md` through `c04-*.md`, and
`d01-*.md`/`d02-*.md` for how each is used.

### Deliberately not wrapped

Live-exploitation and credential-cracking frameworks — Metasploit,
Hydra, Medusa, Hashcat, John the Ripper, Mimikatz, BeEF, RouterSploit,
Commix, and wireless-attack suites (Aircrack-ng, Wifite, Reaver,
hcxdumptool) — are not wrapped as auto-invokable tools here, and
neither are "menu" aggregator repos that bundle dozens of tools under
one installer (`Z4nzu/hackingtool`, `Manisso/fsociety` — both reviewed
and declined; the former explicitly catalogs DDoS and phishing tool
categories, the latter bundles brute-forcers and post-exploitation
tooling). The gap between "confirm a vulnerability with one minimal
PoC" (what every exploitation-category tool here does) and "run a
general-purpose exploitation/credential-cracking framework" is large
enough that wrapping the latter for autonomous use would meaningfully
change this agent's risk profile, not just extend its coverage. These
remain human-operated tools outside the agent's tool registry. If you
want one wrapped with appropriately heavy gating for a specific,
narrow use case, that is a deliberate design decision to make
explicitly, not a default to add by habit.

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

88 tests covering `guardrails.py` (scope/budget/approval enforcement —
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
