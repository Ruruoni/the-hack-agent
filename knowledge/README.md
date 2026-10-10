# Knowledge base

The agent writes a short markdown note here after every run
(`security_agent/memory.py`), and reads them back in as context for future
runs via `KnowledgeBase.load_all()`.

This is the agent's "growth" mechanism: durable, human-reviewable, plain-text
notes committed to git like any other change — not a self-modifying prompt
or binary blob. Review these files in PRs the same way you'd review code.
