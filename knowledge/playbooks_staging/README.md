# Staged playbook drafts — not loaded into the agent's context

Unlike `knowledge/playbooks/*.md`, nothing here is read by
`KnowledgeBase.load_playbooks()` — these `.md.draft` files are output
from `learn_from_repo()`, paired with a staged tool in
`security_agent/tools_staging/`, waiting for human review before
promotion. See `security_agent/tools_staging/README.md` for the
promotion process.
