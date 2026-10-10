"""Tests for the tool layer: every tool must go through guardrails
before doing anything, must report clearly when its binary is missing,
and (where relevant) must escalate its action category correctly.

Subprocess calls are never actually executed here — tools are tested
against guardrails real logic, with `_run_subprocess`/network calls
monkeypatched so these tests have no external dependencies.
"""
from __future__ import annotations

import pytest

from security_agent.guardrails import ApprovalRequired, ScopeViolation
from security_agent.tools import build_default_registry
from security_agent.tools.base import Tool, ToolRegistry
from security_agent.tools.injection import SqlInjectionTestTool
from security_agent.tools.jwt_analysis import JwtAnalyzeTool
from security_agent.tools.recon import PortScanTool


# --------------------------------------------------------------------- base


def test_tool_without_binary_is_always_available():
    class NoBinaryTool(Tool):
        name = "noop"

    assert NoBinaryTool().available() is True


def test_tool_with_missing_binary_is_unavailable():
    class FakeBinaryTool(Tool):
        name = "fake"
        binary = "this-binary-definitely-does-not-exist-anywhere"

    assert FakeBinaryTool().available() is False


def test_registry_registers_and_schemas():
    registry = ToolRegistry()
    registry.register(PortScanTool())
    assert "port_scan" in registry.names()
    schemas = registry.schemas()
    assert schemas[0]["function"]["name"] == "port_scan"


def test_default_registry_has_expected_tools():
    names = build_default_registry().names()
    for expected in (
        "port_scan",
        "subdomain_enum",
        "http_probe",
        "tls_scan",
        "jwt_analyze",
        "web_vuln_scan",
        "directory_bruteforce",
        "http_request",
        "sql_injection_test",
        "ai_agent_redteam",
        "sast_scan",
        "secret_scan",
    ):
        assert expected in names


# -------------------------------------------------------------- port_scan


def test_port_scan_refuses_out_of_scope_target_before_running_anything(guardrails):
    tool = PortScanTool()
    with pytest.raises(ScopeViolation):
        tool.run(guardrails, target="evil.com")


def test_port_scan_reports_missing_binary_cleanly(monkeypatch, guardrails):
    tool = PortScanTool()
    monkeypatch.setattr(tool, "available", lambda: False)
    result = tool.run(guardrails, target="app.example-lab.local")
    assert result.ok is False
    assert "not installed" in result.summary


def test_port_scan_runs_when_authorized_and_available(monkeypatch, guardrails):
    tool = PortScanTool()
    monkeypatch.setattr(tool, "available", lambda: True)
    monkeypatch.setattr(tool, "_run_subprocess", lambda cmd, timeout=300: (0, "22/tcp open ssh", ""))
    result = tool.run(guardrails, target="app.example-lab.local")
    assert result.ok is True
    assert "22/tcp" in result.summary


# ------------------------------------------------------------ jwt_analyze (pure logic, no mocking)


def test_jwt_analyze_flags_alg_none(guardrails):
    import base64
    import json

    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    token = b64({"alg": "none", "typ": "JWT"}) + "." + b64({"sub": "1"}) + "."
    result = JwtAnalyzeTool().run(guardrails, token=token)
    assert result.ok is True
    assert "alg=none" in result.summary


def test_jwt_analyze_flags_missing_exp_and_sensitive_claims(guardrails):
    import base64
    import json

    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    token = b64({"alg": "HS256"}) + "." + b64({"sub": "1", "password": "hunter2"}) + ".sig"
    result = JwtAnalyzeTool().run(guardrails, token=token)
    assert "No 'exp' claim" in result.summary
    assert "password" in result.summary


def test_jwt_analyze_rejects_malformed_token(guardrails):
    result = JwtAnalyzeTool().run(guardrails, token="not-a-jwt")
    assert result.ok is False


# -------------------------------------------------------- sql_injection_test (category escalation)


def test_sql_injection_detect_mode_does_not_require_approval(monkeypatch, make_scope, make_guardrails):
    scope = make_scope(require_human_approval_for=["exploitation"])
    g = make_guardrails(scope, auto_deny_approvals=True)  # would deny if asked
    tool = SqlInjectionTestTool()
    monkeypatch.setattr(tool, "available", lambda: True)
    monkeypatch.setattr(tool, "_run_subprocess", lambda cmd, timeout=900: (0, "not injectable", ""))
    result = tool.run(g, target="app.example-lab.local/item?id=1", dump=False)
    assert result.ok is True  # detect-only never asked for approval, so it ran


def test_sql_injection_dump_mode_is_blocked_without_approval(make_scope, make_guardrails):
    scope = make_scope(require_human_approval_for=["exploitation"])
    g = make_guardrails(scope, auto_deny_approvals=True)
    tool = SqlInjectionTestTool()
    with pytest.raises(ApprovalRequired):
        tool.run(g, target="app.example-lab.local/item?id=1", dump=True)


def test_sql_injection_dump_mode_proceeds_once_approved(monkeypatch, make_scope, make_guardrails):
    scope = make_scope(require_human_approval_for=["exploitation"])
    g = make_guardrails(scope, asker=lambda prompt: True)
    tool = SqlInjectionTestTool()
    monkeypatch.setattr(tool, "available", lambda: True)
    monkeypatch.setattr(tool, "_run_subprocess", lambda cmd, timeout=900: (0, "dumped 1 row", ""))
    result = tool.run(g, target="app.example-lab.local/item?id=1", dump=True)
    assert result.ok is True
    assert result.data["dumped"] is True


def test_sql_injection_dump_mode_blocked_even_if_exploitation_disallowed(make_scope, make_guardrails):
    scope = make_scope(rules_of_engagement={"allow_exploitation": False})
    g = make_guardrails(scope)
    tool = SqlInjectionTestTool()
    with pytest.raises(ScopeViolation):
        tool.run(g, target="app.example-lab.local/item?id=1", dump=True)
