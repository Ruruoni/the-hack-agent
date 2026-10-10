"""The agent loop: plan → call tool → observe → repeat, model-agnostic.

Safety model: the LLM only ever *proposes* a tool call. Every proposal is
re-validated by `Guardrails` before anything executes — the model's output
is treated as untrusted input, never as authorization.
"""
from __future__ import annotations

import json
import logging

from .config import AgentConfig
from .guardrails import ApprovalRequired, BudgetExceeded, Guardrails, ScopeViolation
from .memory import KnowledgeBase
from .providers import ChatResponse, LLMProvider, ToolCall, build_provider
from .report import RunReport
from .tools import ToolRegistry, build_default_registry

logger = logging.getLogger("security_agent")

SYSTEM_PROMPT = """You are an authorized security testing assistant operating \
strictly inside the boundaries of scope.yaml. You can only act on targets \
explicitly allow-listed there; every tool call you propose is independently \
re-checked against that scope before it runs, and will be refused if it \
falls outside it. You cannot and must not attempt to bypass, disable, or \
talk your way around that check.

You have a full OWASP Top 10 (2021) testing methodology preloaded below — \
playbooks/00-methodology.md sets the phase order (scope confirmation → \
passive recon → mapping → vulnerability identification → gated \
exploitation → reporting); playbooks/a01 through a11 give the detail, \
example commands, and tool names for each category (a11 extends beyond \
the official Top 10 to AI agent/LLM targets), from basic checks up to \
advanced, approval-gated confirmation. Follow that methodology rather \
than improvising: match the task in front of you to the relevant \
category playbook(s) before deciding which tool to call next.

playbooks/b01-governance-compliance-mapping.md gives the defensive/\
governance lens on top of that: how to map each finding to NIST CSF 2.0, \
ISO/IEC 27001:2022, CIS Controls v8, and PCI DSS v4.0, and to ground it \
in real-world attacker behavior (breach macro-patterns and MITRE ATT&CK \
technique IDs). Use its reporting template for every finding in your \
final summary, not just the OWASP category fields.

Never propose exploitation, credential testing, or any write/destructive \
action as something that just happens — those require a separate, \
explicitly human-approved path, and the tools that can do them (e.g. \
sql_injection_test with dump=True) will themselves prompt for approval. \
Propose the minimal action that would confirm a finding, not the most \
thorough one.

After using the tools available to you, summarize findings using \
playbooks/b01's reporting template: title, OWASP/category, evidence, \
severity (Critical/High/Medium/Low/Info), breach macro-pattern, MITRE \
ATT&CK tactic/technique, NIST CSF 2.0 function.category, ISO 27001:2022 \
Annex A clause, CIS Control v8 (number + Implementation Group), PCI DSS \
v4.0 requirement (or "not applicable" if no CHD/CDE in scope), and \
concrete remediation. When you are done, or when no more tool calls are \
useful, reply with a final plain-text summary and no further tool calls.

{knowledge}
"""


class SecurityAgent:
    def __init__(
        self,
        config: AgentConfig | None = None,
        guardrails: Guardrails | None = None,
        registry: ToolRegistry | None = None,
        provider: LLMProvider | None = None,
        knowledge: KnowledgeBase | None = None,
        reports_dir=None,
    ):
        self.config = config or AgentConfig()
        # If the operator wants an interactive approval prompt (CLI default),
        # auto_deny is False; in a non-interactive run (CI), there's no
        # stdin to prompt, so default to auto-denying anything gated.
        self.guardrails = guardrails or Guardrails(
            auto_deny_approvals=not self.config.require_human_approval_default
        )
        self.registry = registry or build_default_registry()
        self.provider = provider or build_provider(self.config.provider)
        self.knowledge = knowledge or KnowledgeBase()
        # Injectable so tests don't write into the real reports/ directory.
        self.reports_dir = reports_dir

    def run(self, objective: str) -> RunReport:
        report = RunReport(objective)
        knowledge_text = self.knowledge.load_all() or "(none yet)"
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT.format(knowledge=knowledge_text)},
            {"role": "user", "content": objective},
        ]
        tool_schemas = self.registry.schemas()

        for iteration in range(self.config.max_iterations):
            try:
                self.guardrails.budget.check_runtime()
            except BudgetExceeded as exc:
                report.add_finding(f"Run stopped: {exc}")
                break

            response: ChatResponse = self.provider.chat(messages, tool_schemas)
            self.guardrails.budget.note_llm_tokens(response.usage_tokens)

            if not response.tool_calls:
                if response.content:
                    report.add_finding(response.content.strip())
                    messages.append({"role": "assistant", "content": response.content})
                logger.info("Agent finished after %d iteration(s).", iteration + 1)
                break

            messages.append(
                {
                    "role": "assistant",
                    "content": response.content or "",
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                        }
                        for tc in response.tool_calls
                    ],
                }
            )

            for tc in response.tool_calls:
                result_text = self._execute_tool_call(tc, report)
                messages.append(
                    {"role": "tool", "tool_call_id": tc.id, "name": tc.name, "content": result_text}
                )
        else:
            report.add_finding("Run stopped: max_iterations reached.")

        report_path = report.save(reports_dir=self.reports_dir)
        self.knowledge.write_note(
            f"run-summary-{report.started_at.strftime('%Y%m%d-%H%M%S')}",
            f"Objective: {objective}\n\nSee {report_path.name} for full detail.\n\n"
            + "\n".join(f"- {f}" for f in report.findings),
        )
        return report

    def _execute_tool_call(self, tc: ToolCall, report: RunReport) -> str:
        tool = self.registry.get(tc.name)
        target = (
            tc.arguments.get("target")
            or tc.arguments.get("domain")
            or tc.arguments.get("path")
            or ",".join(tc.arguments.get("targets", []))
            or "unknown"
        )
        if tool is None:
            msg = f"Unknown tool '{tc.name}' — refusing."
            report.log_step(tc.name, target, msg, ok=False)
            return msg

        try:
            result = tool.run(self.guardrails, **tc.arguments)
            report.log_step(tool.name, target, result.summary, ok=result.ok)
            return result.summary[:4000]
        except (ScopeViolation, ApprovalRequired, BudgetExceeded) as exc:
            logger.warning("Tool call refused: %s", exc)
            report.log_step(tool.name, target, f"REFUSED: {exc}", ok=False)
            return f"REFUSED: {exc}"
        except Exception as exc:  # noqa: BLE001
            logger.exception("Tool execution error")
            report.log_step(tool.name, target, f"ERROR: {exc}", ok=False)
            return f"ERROR: {exc}"
