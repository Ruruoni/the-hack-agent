"""End-to-end tests for the web command-center UI (security_agent/ui/server.py).

These prove the actual thing the UI exists for: a run started over HTTP
drives the real SecurityAgent/Guardrails, a gated tool call blocks the
background thread on a real threading.Event, that block is resolved by
POST /api/approve (standing in for a browser click) rather than stdin,
and the job then completes and its report becomes visible through the
read-only endpoints -- all without touching the real scope.yaml,
reports/, or an actual LLM/network.
"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from security_agent.config import AgentConfig
from security_agent.guardrails import AuditLog, Guardrails as RealGuardrails
from security_agent.loop import SecurityAgent as RealSecurityAgent
from security_agent.memory import KnowledgeBase
from security_agent.ui import server as uiserver


class FakeResponse:
    def __init__(self, content, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []
        self.usage_tokens = 5


class FakeToolCall:
    def __init__(self, id, name, arguments):
        self.id = id
        self.name = name
        self.arguments = arguments


class ScriptedProvider:
    """First call proposes a gated tool call; every call after returns a
    plain final message so the run terminates deterministically."""

    def __init__(self):
        self.calls = 0

    def chat(self, messages, tools):
        self.calls += 1
        if self.calls == 1:
            return FakeResponse(
                None,
                tool_calls=[
                    FakeToolCall(
                        "call-1",
                        "credential_test",
                        {
                            "target": "test.example-lab.local",
                            "service": "ssh",
                            "username": "test-account",
                            "password_list": ["x"],
                        },
                    )
                ],
            )
        return FakeResponse("Done. No further action needed.")


@pytest.fixture
def ui_client(tmp_path, make_scope, monkeypatch):
    test_scope = make_scope(
        authorized=True,
        allowed_domains=["*.example-lab.local"],
        require_human_approval_for=["exploitation"],
    )
    test_audit = AuditLog(path=tmp_path / "audit.jsonl")
    reports_dir = tmp_path / "reports"
    knowledge_dir = tmp_path / "knowledge"
    (knowledge_dir / "playbooks").mkdir(parents=True)

    def fake_load_config():
        return AgentConfig()

    def fake_guardrails(asker=None, auto_deny_approvals=False):
        return RealGuardrails(
            asker=asker, auto_deny_approvals=auto_deny_approvals, scope=test_scope, audit=test_audit
        )

    def fake_security_agent(config=None, guardrails=None, on_event=None):
        return RealSecurityAgent(
            config=config,
            guardrails=guardrails,
            on_event=on_event,
            provider=ScriptedProvider(),
            knowledge=KnowledgeBase(root=knowledge_dir),
            reports_dir=reports_dir,
        )

    monkeypatch.setattr(uiserver, "load_config", fake_load_config)
    monkeypatch.setattr(uiserver, "Guardrails", fake_guardrails)
    monkeypatch.setattr(uiserver, "SecurityAgent", fake_security_agent)
    monkeypatch.setattr(uiserver.cfg, "REPORTS_DIR", reports_dir)

    # Fresh per-test job/approval state -- these are module-level dicts.
    uiserver.JOBS.clear()
    uiserver.PENDING_APPROVALS.clear()

    with TestClient(uiserver.app) as client:
        yield client


def _wait_for(predicate, timeout=10.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def test_index_substitutes_category_json(ui_client):
    resp = ui_client.get("/")
    assert resp.status_code == 200
    assert "{{OWASP_CATEGORIES_JSON}}" not in resp.text
    assert "{{SPECIALIZED_CATEGORIES_JSON}}" not in resp.text
    assert '"a01": "Broken Access Control"' in resp.text
    assert '"c01":' in resp.text


def test_get_scope_reports_real_shipped_scope(ui_client):
    resp = ui_client.get("/api/scope")
    assert resp.status_code == 200
    body = resp.json()
    assert "authorized" in body
    assert "require_human_approval_for" in body


def test_list_playbooks_and_knowledge_and_staging(ui_client):
    assert ui_client.get("/api/playbooks").status_code == 200
    assert ui_client.get("/api/knowledge").status_code == 200
    staging = ui_client.get("/api/staging").json()
    assert "tools" in staging and "playbooks" in staging


def test_report_path_traversal_is_rejected(ui_client):
    resp = ui_client.get("/api/reports/../../etc/passwd")
    assert resp.status_code in (400, 404)


def test_report_not_found(ui_client):
    resp = ui_client.get("/api/reports/does-not-exist.md")
    assert resp.status_code == 404


def test_run_blocks_on_approval_then_resolves_via_api(ui_client):
    start = ui_client.post(
        "/api/run",
        json={"mode": "run", "objective": "Test the ssh login on test.example-lab.local", "non_interactive": False},
    )
    assert start.status_code == 200
    job_id = start.json()["job_id"]

    assert _wait_for(lambda: len(uiserver.PENDING_APPROVALS) == 1), "approval request never appeared"
    req_id = next(iter(uiserver.PENDING_APPROVALS))
    pending = uiserver.PENDING_APPROVALS[req_id]
    assert pending.job_id == job_id
    assert pending.category == "exploitation"

    approvals = ui_client.get("/api/approvals").json()
    assert any(a["request_id"] == req_id for a in approvals)

    approve_resp = ui_client.post(f"/api/approve/{req_id}", json={"approved": True})
    assert approve_resp.status_code == 200

    assert _wait_for(lambda: uiserver.JOBS[job_id].status != "running"), "job never finished"
    job = ui_client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "finished"

    # Approval was granted, so the tool actually ran past the gate (and
    # failed only because hydra isn't installed on this runner) rather
    # than being refused for lack of approval.
    assert "REFUSED" not in job["summary"]

    reports = ui_client.get("/api/reports").json()
    assert len(reports) == 1
    report_text = ui_client.get(f"/api/reports/{reports[0]['path']}").text
    assert "credential_test" in report_text


def test_run_denied_approval_shows_refusal(ui_client):
    start = ui_client.post(
        "/api/run",
        json={"mode": "run", "objective": "Test the ssh login on test.example-lab.local", "non_interactive": False},
    )
    job_id = start.json()["job_id"]

    assert _wait_for(lambda: len(uiserver.PENDING_APPROVALS) == 1)
    req_id = next(iter(uiserver.PENDING_APPROVALS))

    ui_client.post(f"/api/approve/{req_id}", json={"approved": False})

    assert _wait_for(lambda: uiserver.JOBS[job_id].status != "running")
    job = ui_client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "finished"

    # The job summary is the model's final free-text message, which the
    # scripted provider always returns regardless of approval outcome --
    # the actual proof the denial took effect is the tool step log in the
    # saved report, not the summary field.
    reports = ui_client.get("/api/reports").json()
    assert len(reports) == 1
    report_text = ui_client.get(f"/api/reports/{reports[0]['path']}").text
    assert "REFUSED" in report_text
    assert "Human denied approval" in report_text


def test_approve_unknown_request_id_is_404(ui_client):
    resp = ui_client.post("/api/approve/does-not-exist", json={"approved": True})
    assert resp.status_code == 404


def test_websocket_receives_live_events(ui_client):
    with ui_client.websocket_connect("/ws") as ws:
        start = ui_client.post(
            "/api/run",
            json={
                "mode": "run",
                "objective": "Test the ssh login on test.example-lab.local",
                "non_interactive": False,
            },
        )
        job_id = start.json()["job_id"]

        seen_types = []
        req_id = None
        deadline = time.time() + 10
        while time.time() < deadline and "approval_requested" not in seen_types:
            ev = ws.receive_json()
            seen_types.append(ev["type"])
            if ev["type"] == "approval_requested":
                req_id = ev["request_id"]

        assert req_id is not None, f"never saw approval_requested, saw: {seen_types}"
        assert "run_started" in seen_types
        assert "tool_call_proposed" in seen_types

        ui_client.post(f"/api/approve/{req_id}", json={"approved": True})

        while time.time() < deadline and "job_finished" not in seen_types:
            ev = ws.receive_json()
            seen_types.append(ev["type"])

        assert "approval_resolved" in seen_types
        assert "job_finished" in seen_types
