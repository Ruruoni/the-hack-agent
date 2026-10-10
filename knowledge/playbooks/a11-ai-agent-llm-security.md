# A11 (extension) — AI Agent / LLM Security

Not part of the original OWASP Top 10 (2021), but the same discipline
applied to AI agent and LLM-backed targets — maps to the OWASP Top 10 for
LLM Applications. Use this playbook when the in-scope target is itself an
AI agent, chatbot, or LLM-backed API, rather than a traditional web app.

## What it is
LLM-backed systems fail in ways traditional web app testing doesn't
cover: the "input" is natural language the model itself interprets, so
validation has to happen semantically, not just syntactically.

## Basic
- Map the target's surface: what can a user send it (chat input, a
  document it's asked to summarize, a tool/plugin it can call), and what
  can it do as a result (call APIs, write files, spend money, send
  messages)? The more it can *do*, the higher the stakes of every
  category below.
- Baseline prompt-injection probe: ask the agent, in plain language, to
  ignore its prior instructions and reveal its system prompt or do
  something outside its stated purpose. A model that complies
  immediately on an unsophisticated probe is a strong, cheap finding.
- `ai_agent_redteam` (hackagent) baseline sweep against the endpoint —
  covers jailbreak and prompt-injection techniques researchers have
  published (PAIR, TAP, Crescendo, AutoDAN, cipher-based obfuscation,
  and more) without you having to craft each one by hand.

## Intermediate
- **Prompt injection (direct):** craft inputs that attempt to override
  the system prompt or inject new instructions the model treats as
  authoritative.
- **Prompt injection (indirect):** if the agent reads external content
  (a webpage, a document, a tool's output) as part of its task, plant an
  instruction *in that content* (on a page/resource you control, in
  scope) and see if the agent follows it instead of the user's actual
  request. `ai_agent_redteam --technique indirect_prompt_injection`
  covers this class.
- **Goal hijacking:** does a multi-step/autonomous agent stay on the
  user's original objective, or can injected content redirect it to a
  different one entirely? (`--technique goal_hijack`.)
- **Tool/plugin misuse:** if the agent has tools (file access, code
  execution, payments, sending messages), can a crafted input make it
  invoke one in a way the user never asked for, or with
  attacker-controlled arguments?
- **Excessive agency:** does the agent ask for confirmation before
  consequential actions (sending money, deleting data, posting
  publicly), or does it just act? Absence of a confirmation step on a
  consequential tool is a finding even without triggering it.
- **Insecure output handling:** if the agent's output is rendered
  somewhere else (a web page, another system that parses it as
  structured data), can the model be induced to emit something that
  becomes XSS, a command, or malformed data downstream? Cross-reference
  with the A03 injection playbook on the rendering side.

## Advanced (approval-gated)
- Demonstrating actual impact of a successful jailbreak/goal-hijack
  (e.g. getting the agent to actually call a sensitive tool, not just
  produce text that *would* if continued) requires explicit approval,
  the same as any other exploitation step — propose the single, minimal
  action that would prove it, never a chained sequence.
- Extracting the system prompt or any embedded credentials/secrets via a
  successful injection is itself a finding; stop there — don't use what
  you extracted to go further without a separate approval.

## Tools
`ai_agent_redteam` (hackagent — https://github.com/AISecurityLab/hackagent,
optional dependency, `pip install hackagent`), plus manual
`http_request` for hand-crafted probes against the target's API.

## Remediation to report
Treat all model input (including tool/retrieval output fed back to the
model) as untrusted; never let the system prompt alone be the security
boundary; require explicit user confirmation before consequential tool
calls; validate/sanitize model output before it's rendered or parsed
downstream; and log+monitor for injection/jailbreak attempt patterns the
way A09 asks for conventional auth failures.
