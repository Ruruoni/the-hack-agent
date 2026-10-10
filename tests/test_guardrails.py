"""Regression tests for the single file everything else here depends on
being correct: security_agent/guardrails.py.
"""
from __future__ import annotations

import json
import time

import pytest
import yaml

from security_agent.guardrails import (
    ApprovalGate,
    ApprovalRequired,
    AuditLog,
    BudgetExceeded,
    BudgetTracker,
    Guardrails,
    Scope,
    ScopeViolation,
)


# ---------------------------------------------------------------- Scope.load


def test_scope_load_missing_file_refuses(tmp_path):
    with pytest.raises(ScopeViolation):
        Scope.load(path=tmp_path / "does-not-exist.yaml")


def test_scope_load_reads_real_yaml(tmp_path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        yaml.dump(
            {
                "authorized": True,
                "authorized_by": "alice",
                "authorization_reference": "ref-123",
                "targets": {
                    "allowed_domains": ["*.lab.local"],
                    "allowed_cidrs": ["10.0.0.0/24"],
                },
                "rules_of_engagement": {"allow_passive_recon": True},
                "budgets": {"max_tool_calls_per_run": 5},
                "require_human_approval_for": ["exploitation"],
            }
        )
    )
    s = Scope.load(path=scope_file)
    assert s.authorized is True
    assert s.allowed_domains == ["*.lab.local"]
    assert s.budgets["max_tool_calls_per_run"] == 5


# ---------------------------------------------------------- check_authorized


def test_check_authorized_refuses_when_false(make_scope):
    s = make_scope(authorized=False)
    with pytest.raises(ScopeViolation):
        s.check_authorized()


def test_check_authorized_refuses_when_missing_signoff_fields(make_scope):
    s = make_scope(authorized=True, authorized_by="", authorization_reference="")
    with pytest.raises(ScopeViolation):
        s.check_authorized()


def test_check_authorized_passes_when_fully_signed_off(scope):
    scope.check_authorized()  # should not raise


# ---------------------------------------------------------------- check_target


def test_check_target_allows_matching_domain(scope):
    scope.check_target("app.example-lab.local")  # should not raise


def test_check_target_allows_matching_cidr(scope):
    scope.check_target("10.10.10.42")  # should not raise


def test_check_target_strips_scheme_and_port(scope):
    scope.check_target("https://app.example-lab.local:8443/path")  # should not raise


def test_check_target_refuses_out_of_scope_domain(scope):
    with pytest.raises(ScopeViolation):
        scope.check_target("evil.com")


def test_check_target_refuses_out_of_scope_ip(scope):
    with pytest.raises(ScopeViolation):
        scope.check_target("8.8.8.8")


def test_check_target_denylist_wins_over_allowlist(make_scope):
    s = make_scope(
        allowed_domains=["*.example-lab.local"],
        denied_domains=["admin.example-lab.local"],
    )
    s.check_target("app.example-lab.local")  # fine
    with pytest.raises(ScopeViolation):
        s.check_target("admin.example-lab.local")  # explicitly denied


def test_check_target_refuses_everything_when_unauthorized(make_scope):
    s = make_scope(authorized=False)
    with pytest.raises(ScopeViolation):
        s.check_target("app.example-lab.local")


# ------------------------------------------------------------ action category


def test_check_action_allowed_passes_when_true(scope):
    scope.check_action_allowed("passive_recon")  # should not raise


def test_check_action_allowed_refuses_when_false(make_scope):
    s = make_scope(rules_of_engagement={"allow_active_scanning": False})
    with pytest.raises(ScopeViolation):
        s.check_action_allowed("active_scanning")


def test_needs_human_approval(make_scope):
    s = make_scope(require_human_approval_for=["exploitation"])
    assert s.needs_human_approval("exploitation") is True
    assert s.needs_human_approval("passive_recon") is False


# -------------------------------------------------------------- BudgetTracker


def test_budget_tracker_enforces_max_tool_calls(make_scope):
    s = make_scope(budgets={"max_tool_calls_per_run": 2})
    tracker = BudgetTracker(s)
    tracker.note_tool_call()
    tracker.note_tool_call()
    with pytest.raises(BudgetExceeded):
        tracker.note_tool_call()


def test_budget_tracker_enforces_max_tokens(make_scope):
    s = make_scope(budgets={"max_llm_tokens_per_run": 100})
    tracker = BudgetTracker(s)
    tracker.note_llm_tokens(60)
    with pytest.raises(BudgetExceeded):
        tracker.note_llm_tokens(60)


def test_budget_tracker_enforces_runtime(make_scope):
    # Note: 0/absent is "unlimited" by the same falsy-check convention as
    # the other budgets (see test_budget_tracker_unset_caps_never_trigger),
    # so use a tiny positive value to actually exercise the cap.
    s = make_scope(budgets={"max_runtime_minutes": 1e-6})
    tracker = BudgetTracker(s)
    time.sleep(0.01)
    with pytest.raises(BudgetExceeded):
        tracker.check_runtime()


def test_budget_tracker_unset_caps_never_trigger(make_scope):
    s = make_scope(budgets={})
    tracker = BudgetTracker(s)
    for _ in range(50):
        tracker.note_tool_call()
    tracker.note_llm_tokens(10_000_000)
    tracker.check_runtime()  # none of these should raise


def test_budget_tracker_throttle_does_not_block_when_fast_enough(make_scope):
    s = make_scope(rules_of_engagement={"max_requests_per_second": 1000})
    tracker = BudgetTracker(s)
    start = time.monotonic()
    tracker.throttle("host-a")
    tracker.throttle("host-a")
    assert time.monotonic() - start < 0.5


# ---------------------------------------------------------------- AuditLog


def test_audit_log_appends_jsonl(tmp_path):
    log = AuditLog(path=tmp_path / "audit.jsonl")
    log.record("something_happened", tool="x", target="y")
    log.record("something_else", tool="x", target="y")
    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["event"] == "something_happened"
    assert first["tool"] == "x"
    assert "ts" in first


# ---------------------------------------------------------------- ApprovalGate


def test_approval_gate_skips_when_category_not_gated(scope):
    gate = ApprovalGate(scope, asker=lambda prompt: False)
    gate.require("passive_recon", "just recon")  # should not raise even though asker denies


def test_approval_gate_approves_when_asker_says_yes(scope):
    gate = ApprovalGate(scope, asker=lambda prompt: True)
    gate.require("exploitation", "a gated action")  # should not raise


def test_approval_gate_denies_when_asker_says_no(scope):
    gate = ApprovalGate(scope, asker=lambda prompt: False)
    with pytest.raises(ApprovalRequired):
        gate.require("exploitation", "a gated action")


def test_approval_gate_auto_denies_when_non_interactive(scope):
    gate = ApprovalGate(scope, auto_deny=True)
    with pytest.raises(ApprovalRequired):
        gate.require("exploitation", "a gated action")


# -------------------------------------------------------- Guardrails (integration)


def test_guardrails_authorize_tool_call_happy_path(guardrails):
    guardrails.authorize_tool_call(
        "port_scan", "app.example-lab.local", "passive_recon", "a routine scan"
    )  # should not raise


def test_guardrails_authorize_tool_call_refuses_out_of_scope_target(guardrails):
    with pytest.raises(ScopeViolation):
        guardrails.authorize_tool_call("port_scan", "evil.com", "passive_recon", "nope")


def test_guardrails_authorize_tool_call_refuses_disallowed_category(make_scope, make_guardrails):
    s = make_scope(rules_of_engagement={"allow_active_scanning": False})
    g = make_guardrails(s)
    with pytest.raises(ScopeViolation):
        g.authorize_tool_call("web_vuln_scan", "app.example-lab.local", "active_scanning", "scan")


def test_guardrails_authorize_tool_call_blocks_gated_action_without_approval(make_scope, make_guardrails):
    s = make_scope(require_human_approval_for=["exploitation"])
    g = make_guardrails(s, auto_deny_approvals=True)
    with pytest.raises(ApprovalRequired):
        g.authorize_tool_call(
            "sql_injection_test", "app.example-lab.local", "exploitation", "dump data"
        )


def test_guardrails_authorize_tool_call_allows_gated_action_with_approval(make_scope, make_guardrails):
    s = make_scope(require_human_approval_for=["exploitation"])
    g = make_guardrails(s, asker=lambda prompt: True)
    g.authorize_tool_call(
        "sql_injection_test", "app.example-lab.local", "exploitation", "dump data"
    )  # should not raise


def test_guardrails_authorize_tool_call_enforces_budget(make_scope, make_guardrails):
    s = make_scope(budgets={"max_tool_calls_per_run": 1})
    g = make_guardrails(s)
    g.authorize_tool_call("port_scan", "app.example-lab.local", "passive_recon", "first")
    with pytest.raises(BudgetExceeded):
        g.authorize_tool_call("port_scan", "app.example-lab.local", "passive_recon", "second")


def test_guardrails_refuses_construction_when_unauthorized(make_scope, make_guardrails):
    # Fails fast at construction, not only on the first tool call.
    s = make_scope(authorized=False)
    with pytest.raises(ScopeViolation):
        make_guardrails(s)


def test_guardrails_authorize_local_action_ignores_domain_scope(guardrails):
    # Local source-code tools (sast/secret scan) aren't network targets,
    # so they should not be checked against allowed_domains/allowed_cidrs.
    guardrails.authorize_local_action("sast_scan", "/some/local/path", "scan local checkout")


def test_guardrails_writes_audit_entries(make_scope, tmp_path):
    audit = AuditLog(path=tmp_path / "audit.jsonl")
    g = Guardrails(scope=make_scope(), audit=audit)
    g.authorize_tool_call("port_scan", "app.example-lab.local", "passive_recon", "scan")
    g.record_result("port_scan", "app.example-lab.local", "found 2 open ports")
    g.record_refusal("web_vuln_scan", "evil.com", "out of scope")

    events = [json.loads(line)["event"] for line in audit.path.read_text().strip().splitlines()]
    assert "tool_call_authorized" in events
    assert "tool_call_result" in events
    assert "tool_call_refused" in events
