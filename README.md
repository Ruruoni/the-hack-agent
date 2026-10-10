# the-hack-agent

An authorization-gated, model-agnostic, self-growing security testing
agent. Every action is checked in code against `scope.yaml` before it
runs — the model proposes, the guardrails dispose.

See [`security_agent/README.md`](security_agent/README.md) for setup,
usage, and how the self-growth / eval-gate loop works.

## Quick start

1. Edit `scope.yaml`: set `authorized: true` only once you have real
   written permission to test the targets you list there.
2. Pick a brain (free local via Ollama, free hosted via Groq, or
   Anthropic) — see `security_agent/README.md` for the env vars.
3. ```bash
   pip install -r security_agent/requirements.txt
   python -m security_agent.cli check-scope
   python -m security_agent.cli run "Enumerate subdomains of example-lab.local and summarize findings."
   ```

## Layout

```
scope.yaml              # human-owned authorization boundary
security_agent/         # guardrails, LLM providers, tools, agent loop, CLI
knowledge/              # growth memory — notes written after each run
reports/                # per-run markdown reports + audit.jsonl (gitignored)
evals/                  # regression gate — score agent changes before merging
CODEOWNERS              # protects scope.yaml / guardrails.py from unreviewed changes
.github/workflows/      # eval-gate CI
```
