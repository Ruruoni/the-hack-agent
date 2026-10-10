"""Shared fixtures for the security_agent test suite.

Every test builds its own throwaway Scope/AuditLog rather than touching
the real scope.yaml or reports/audit.jsonl — see guardrails.py's
Guardrails(scope=..., audit=...) injection points.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from security_agent.guardrails import AuditLog, Guardrails, Scope


@pytest.fixture
def make_scope():
    """Factory: make_scope(**overrides) -> Scope, authorized by default
    for *.example-lab.local / 10.10.10.0/24, with passive_recon and
    active_scanning allowed and exploitation requiring approval.
    """

    def _make(**overrides) -> Scope:
        defaults = dict(
            authorized=True,
            authorized_by="test-suite",
            authorization_reference="test-ref",
            allowed_domains=["*.example-lab.local"],
            allowed_cidrs=["10.10.10.0/24"],
            denied_domains=[],
            denied_cidrs=[],
            rules_of_engagement={
                "allow_passive_recon": True,
                "allow_active_scanning": True,
                "allow_exploitation": True,
                "allow_destructive_actions": False,
                "allow_denial_of_service": False,
                "max_requests_per_second": 1000,  # don't slow down tests
            },
            budgets={},
            require_human_approval_for=["exploitation"],
        )
        defaults.update(overrides)
        return Scope(**defaults)

    return _make


@pytest.fixture
def scope(make_scope) -> Scope:
    return make_scope()


@pytest.fixture
def audit_log(tmp_path: Path) -> AuditLog:
    return AuditLog(path=tmp_path / "audit.jsonl")


@pytest.fixture
def make_guardrails(audit_log):
    """Factory: make_guardrails(scope, auto_deny_approvals=False, asker=None)."""

    def _make(scope: Scope, auto_deny_approvals: bool = False, asker=None) -> Guardrails:
        return Guardrails(
            scope=scope, audit=audit_log, auto_deny_approvals=auto_deny_approvals, asker=asker
        )

    return _make


@pytest.fixture
def guardrails(scope, make_guardrails) -> Guardrails:
    return make_guardrails(scope)
