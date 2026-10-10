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
   `gitleaks`.

## Running

```bash
pip install -r security_agent/requirements.txt
python -m security_agent.cli check-scope
python -m security_agent.cli run "Enumerate subdomains of example-lab.local, probe which are alive, and run a safe web vuln scan on each."
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

## Self-growth, safely

The agent doesn't rewrite its own code unsupervised. Growth happens two ways:

1. **Knowledge growth** — `knowledge/*.md` notes accumulate automatically
   and get reviewed/pruned like any other file in PRs.
2. **Capability growth** — adding a new tool in `security_agent/tools/`,
   adjusting the prompt in `loop.py`, or loosening `scope.yaml` is a normal
   pull request. `.github/workflows/security-agent-eval.yml` runs
   `evals/run_eval.py` against your own lab targets on every such PR; a
   change that regresses the pass rate shouldn't merge. `CODEOWNERS`
   requires your review on `scope.yaml` and `guardrails.py` specifically,
   so the agent's own proposed changes can never loosen its safety
   boundary without a human approving it.

## Extending

Add a new tool by subclassing `security_agent.tools.base.Tool`, giving it
an `action_category` (`passive_recon` / `active_scanning` / `exploitation`),
and registering it in `security_agent/tools/__init__.py`. Every tool call
still goes through `Guardrails.authorize_tool_call()` — there's no path
that skips it.
