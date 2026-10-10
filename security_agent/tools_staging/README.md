# Staged tool drafts — not live, not registered, not executed

Files here are output from `security_agent.learning.LearningAgent.learn_from_repo()`.
They are plain `.py.draft` text, never imported by any Python module
(the `.draft` suffix keeps them out of the normal `.py` import path and
out of `tools/__init__.py`'s registry) and never executed by anything
in this repo.

A draft here means: a model, given a repository's README and file
tree, proposed that this would be a reasonable tool to add and sketched
what the code might look like. It is a starting point for a human to
review, not a finished, trusted addition.

## Promoting a draft

1. Read the draft critically — verify the source repo's actual license,
   re-check it against `security_agent/README.md`'s "Deliberately not
   wrapped" criteria yourself (don't take the model's classification as
   final), and rewrite the code as needed to match the real conventions
   in `security_agent/tools/`.
2. Move it to `security_agent/tools/<name>.py`, register it in
   `security_agent/tools/__init__.py`, and move any staged playbook out
   of `knowledge/playbooks_staging/` into `knowledge/playbooks/`.
3. Add tests in `tests/test_tools.py` (see any existing tool for the
   pattern — every tool's guardrail integration gets a real test).
4. Open it as a normal PR — `CODEOWNERS` and the eval-gate workflow
   apply exactly as they do to any other change here.

Nothing about a file existing in this directory grants it any
capability — it's text, reviewed the same way every other addition to
this repo has been.
