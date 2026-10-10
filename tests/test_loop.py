"""End-to-end tests of the agent loop itself: plan -> tool call ->
observe -> repeat, with a fake provider and fake tools standing in for
a real LLM and real subprocess-backed tools. No network, no GPU, no API
key needed.
"""
from __future__ import annotations

import json

import pytest

from security_agent.config import AgentConfig
from security_agent.guardrails import ScopeViolation
from security_agent.loop import SecurityAgent
from security_agent.memory import KnowledgeBase
from security_agent.providers import ChatResponse, ToolCall
from security_agent.tools.base import Tool, ToolRegistry, ToolResult


class FakeTool(Tool):
    name = "fake_tool"
    description = "A fake tool for testing."
    action_category = "passive_recon"
    parameters = {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}

    def run(self, guardrails, target, **_):
        guardrails.authorize_tool_call(self.name, target, self.action_category, "fake action")
        return ToolResult(ok=True, summary=f"fake result for {target}", data={})


class ScriptedProvider:
    """Replays a fixed sequence of ChatResponse objects, one per .chat() call."""

    def __init__(self, responses: list[ChatResponse]):
        self._responses = list(responses)
        self.calls = 0

    def chat(self, messages, tools):
        self.calls += 1
        if not self._responses:
            raise AssertionError("ScriptedProvider ran out of scripted responses")
        return self._responses.pop(0)


def _agent(tmp_path, scope, provider, registry=None, max_iterations=10):
    from security_agent.guardrails import Guardrails

    config = AgentConfig()
    config.max_iterations = max_iterations
    guardrails = Guardrails(scope=scope, auto_deny_approvals=True)
    knowledge = KnowledgeBase(root=tmp_path / "knowledge")
    reg = registry or ToolRegistry()
    if not registry:
        reg.register(FakeTool())
    return SecurityAgent(
        config=config,
        guardrails=guardrails,
        registry=reg,
        provider=provider,
        knowledge=knowledge,
        reports_dir=tmp_path / "reports",
    )


def test_agent_stops_immediately_when_model_returns_no_tool_calls(tmp_path, scope):
    provider = ScriptedProvider(
        [ChatResponse(content="Nothing to do here.", tool_calls=[], raw={}, usage_tokens=5)]
    )
    agent = _agent(tmp_path, scope, provider)
    report = agent.run("do nothing")
    assert report.findings == ["Nothing to do here."]
    assert report.steps == []
    assert provider.calls == 1


def test_agent_executes_a_proposed_tool_call(tmp_path, scope):
    provider = ScriptedProvider(
        [
            ChatResponse(
                content=None,
                tool_calls=[ToolCall(id="1", name="fake_tool", arguments={"target": "app.example-lab.local"})],
                raw={},
                usage_tokens=10,
            ),
            ChatResponse(content="Done.", tool_calls=[], raw={}, usage_tokens=5),
        ]
    )
    agent = _agent(tmp_path, scope, provider)
    report = agent.run("probe the lab host")
    assert len(report.steps) == 1
    assert report.steps[0]["tool"] == "fake_tool"
    assert report.steps[0]["ok"] is True
    assert "app.example-lab.local" in report.steps[0]["summary"]


def test_agent_refuses_out_of_scope_tool_call_without_crashing(tmp_path, scope):
    provider = ScriptedProvider(
        [
            ChatResponse(
                content=None,
                tool_calls=[ToolCall(id="1", name="fake_tool", arguments={"target": "evil.com"})],
                raw={},
                usage_tokens=10,
            ),
            ChatResponse(content="Noted the refusal.", tool_calls=[], raw={}, usage_tokens=5),
        ]
    )
    agent = _agent(tmp_path, scope, provider)
    report = agent.run("try an out-of-scope host")
    assert report.steps[0]["ok"] is False
    assert "REFUSED" in report.steps[0]["summary"]
    assert "evil.com" in report.steps[0]["summary"]


def test_agent_handles_unknown_tool_name_gracefully(tmp_path, scope):
    provider = ScriptedProvider(
        [
            ChatResponse(
                content=None,
                tool_calls=[ToolCall(id="1", name="nonexistent_tool", arguments={"target": "x"})],
                raw={},
                usage_tokens=10,
            ),
            ChatResponse(content="done", tool_calls=[], raw={}, usage_tokens=5),
        ]
    )
    agent = _agent(tmp_path, scope, provider)
    report = agent.run("call a tool that doesn't exist")
    assert report.steps[0]["ok"] is False
    assert "Unknown tool" in report.steps[0]["summary"]


def test_agent_stops_at_max_iterations_if_model_never_finishes(tmp_path, scope):
    always_calls_tool = ChatResponse(
        content=None,
        tool_calls=[ToolCall(id="1", name="fake_tool", arguments={"target": "app.example-lab.local"})],
        raw={},
        usage_tokens=1,
    )
    provider = ScriptedProvider([always_calls_tool] * 3)
    agent = _agent(tmp_path, scope, provider, max_iterations=3)
    report = agent.run("loop forever")
    assert "max_iterations reached" in report.findings[-1]
    assert provider.calls == 3


def test_agent_writes_report_and_knowledge_note(tmp_path, scope):
    provider = ScriptedProvider([ChatResponse(content="All clear.", tool_calls=[], raw={}, usage_tokens=5)])
    agent = _agent(tmp_path, scope, provider)
    agent.run("quick check")

    report_files = list((tmp_path / "reports").glob("run-*.md"))
    assert len(report_files) == 1
    assert "All clear." in report_files[0].read_text()

    note_files = [
        f for f in (tmp_path / "knowledge").glob("*.md") if f.name.lower() != "readme.md"
    ]
    assert len(note_files) == 1
    assert "quick check" in note_files[0].read_text()


def test_agent_loads_playbooks_into_system_prompt(tmp_path, scope):
    captured_messages = {}

    class CapturingProvider:
        def chat(self, messages, tools):
            captured_messages["messages"] = messages
            return ChatResponse(content="ok", tool_calls=[], raw={}, usage_tokens=1)

    agent = _agent(tmp_path, scope, CapturingProvider())
    # seed a playbook the agent should pick up
    (agent.knowledge.playbooks_dir / "00-test.md").write_text("UNIQUE_PLAYBOOK_MARKER")
    agent.run("anything")

    system_msg = captured_messages["messages"][0]
    assert system_msg["role"] == "system"
    assert "UNIQUE_PLAYBOOK_MARKER" in system_msg["content"]


def test_security_agent_construction_refuses_when_scope_unauthorized(make_scope):
    from security_agent.guardrails import Guardrails

    with pytest.raises(ScopeViolation):
        Guardrails(scope=make_scope(authorized=False))
