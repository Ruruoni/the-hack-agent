"""AI agent / LLM security testing — wraps the `hackagent` CLI
(https://github.com/AISecurityLab/hackagent, Apache-2.0), an external,
optional dependency (`pip install hackagent`), not vendored into this
repo. Runs research-backed attack techniques (prompt injection,
jailbreak attempts, goal-hijacking probes) against an in-scope AI
agent/LLM endpoint to evaluate its robustness — the same non-destructive,
detect-and-report posture as every other tool here.
"""
from __future__ import annotations

from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult


class AiAgentRedTeamTool(Tool):
    name = "ai_agent_redteam"
    description = (
        "Run AI agent / LLM security probes (prompt injection, jailbreak "
        "attempts, goal-hijacking) against an in-scope AI agent/LLM API "
        "endpoint using the hackagent toolkit, to evaluate whether it "
        "resists these techniques. Non-destructive: it sends crafted "
        "prompts and scores the responses, it does not act on whatever "
        "the target agent might be tricked into doing."
    )
    action_category = "active_scanning"
    binary = "hackagent"
    parameters = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "In-scope API endpoint of the AI agent/LLM being tested.",
            },
            "technique": {
                "type": "string",
                "description": (
                    "Attack technique/objective, e.g. 'jailbreak', "
                    "'indirect_prompt_injection', 'goal_hijack'. Default: a "
                    "quick baseline sweep."
                ),
            },
        },
        "required": ["target"],
    }

    def run(
        self, guardrails: Guardrails, target: str, technique: str | None = None, **_: Any
    ) -> ToolResult:
        guardrails.authorize_tool_call(
            self.name,
            target,
            self.action_category,
            f"hackagent {technique or 'baseline'} probe against {target}",
        )
        if not self.available():
            msg = (
                "hackagent is not installed on this runner "
                "(pip install hackagent; see knowledge/playbooks/a11-ai-agent-llm-security.md)."
            )
            guardrails.record_refusal(self.name, target, msg)
            return ToolResult(ok=False, summary=msg, data={})

        cmd = ["hackagent", "attack", "--target", target]
        if technique:
            cmd += ["--technique", technique]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=600)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, target, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, target, (out or err)[:500])
        return ToolResult(ok=rc == 0, summary=out or err, data={"returncode": rc})
