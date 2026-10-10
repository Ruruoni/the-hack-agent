# Knowledge base

Two kinds of memory live here (see `security_agent/memory.py`):

- **`playbooks/`** — curated, human-written OWASP Top 10 (2021)
  methodology, loaded in full into every run's system prompt. This is
  what makes the agent "ready equipped" the moment a model is wired up —
  review/edit these the way you'd review code; they're not written by
  the agent.
- **Everything else here** — short notes the agent writes after each run
  (`security_agent/memory.py`'s `write_note`), read back in up to a size
  budget as "growth" memory. Plain text, committed to git, reviewable in
  PRs like any other change — not a self-modifying prompt or binary blob.
