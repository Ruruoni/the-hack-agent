# the-hack-agent

An authorization-gated, model-agnostic, self-growing security testing
agent. Every action is checked in code against `scope.yaml` before it
runs — the model proposes, the guardrails dispose.

It ships pre-equipped with a full OWASP Top 10 (2021) testing
methodology (`knowledge/playbooks/`) and the tools to act on it — plug
in any model and it's ready on the first run, no training step. That's
*injection* (pasted into the prompt every run); `training/` also offers
*digestion* — an optional pipeline to actually fine-tune an open model's
weights on this same methodology instead.

See [`security_agent/README.md`](security_agent/README.md) for setup,
usage, the built-in OWASP playbooks, and how the self-growth / eval-gate
loop works, and [`training/README.md`](training/README.md) for the
fine-tuning pipeline.

## Quick start

1. Edit `scope.yaml`: set `authorized: true` only once you have real
   written permission to test the targets you list there.
2. Pick a brain (free local via Ollama, free hosted via Groq, or
   Anthropic) — see `security_agent/README.md` for the env vars.
3. ```bash
   pip install -r security_agent/requirements.txt
   python -m security_agent.cli check-scope
   python -m security_agent.cli owasp-scan example-lab.local   # full OWASP Top 10 sweep
   python -m security_agent.cli list-playbooks                 # see what's loaded
   python -m security_agent.cli learn https://github.com/org/tool  # self-learn, drafts only
   ```

## Layout

```
scope.yaml                       # human-owned authorization boundary
security_agent/                  # guardrails, LLM providers, tools, agent loop, CLI
security_agent/tools_staging/    # draft tools from `cli learn` -- never auto-registered
knowledge/playbooks/             # built-in OWASP Top 10 methodology (curated, always loaded)
knowledge/playbooks_staging/     # draft playbooks from `cli learn` -- never auto-loaded
knowledge/*.md                   # growth memory — notes the agent writes after each run
reports/                         # per-run markdown reports + audit.jsonl (gitignored)
evals/                           # regression gate — score agent changes before merging
CODEOWNERS                       # protects scope.yaml / guardrails.py from unreviewed changes
.github/workflows/               # eval-gate CI
training/                        # optional: fine-tune an open model on the playbooks (digestion, not injection)
```
