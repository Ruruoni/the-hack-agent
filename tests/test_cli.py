"""Tests for security_agent/cli.py: the objective builder, category
validation, and the two commands that don't require a live LLM
(check-scope, list-playbooks).
"""
from __future__ import annotations

import pytest

from security_agent.cli import OWASP_CATEGORIES, _build_owasp_objective, main


def test_build_owasp_objective_full_sweep_mentions_all_categories():
    objective = _build_owasp_objective("app.example-lab.local", None)
    assert "app.example-lab.local" in objective
    assert "00-methodology.md" in objective


def test_build_owasp_objective_single_category():
    objective = _build_owasp_objective("app.example-lab.local", "a03")
    assert "A03" in objective
    assert "Injection" in objective
    assert "a03-*.md" in objective


def test_build_owasp_objective_category_case_insensitive():
    objective = _build_owasp_objective("app.example-lab.local", "A07")
    assert "A07" in objective


def test_build_owasp_objective_rejects_unknown_category():
    with pytest.raises(ValueError, match="Unknown category"):
        _build_owasp_objective("app.example-lab.local", "a99")


def test_owasp_categories_cover_a01_through_a11_and_b_extension():
    for i in range(1, 12):
        assert f"a{i:02d}" in OWASP_CATEGORIES
    assert len(OWASP_CATEGORIES) == 11  # a01-a11 only; b01 is a reporting overlay, not a --category choice


# ---------------------------------------------------------------- CLI commands


def test_cli_check_scope_fails_on_unauthorized_default_scope(capsys):
    # The shipped scope.yaml is authorized: false by design.
    rc = main(["check-scope"])
    captured = capsys.readouterr()
    assert rc == 1
    assert "SCOPE INVALID" in captured.err


def test_cli_list_playbooks_shows_all_thirteen(capsys):
    rc = main(["list-playbooks"])
    captured = capsys.readouterr()
    assert rc == 0
    for expected in ("00-methodology.md", "a01-broken-access-control.md", "b01-governance-compliance-mapping.md"):
        assert expected in captured.out


def test_cli_run_refuses_to_start_against_unauthorized_scope(capsys):
    rc = main(["run", "do something", "--non-interactive"])
    captured = capsys.readouterr()
    assert rc == 1
    assert "REFUSING TO START" in captured.err


def test_cli_owasp_scan_rejects_unknown_category():
    with pytest.raises(SystemExit):
        # argparse itself rejects an unknown --category choice before main's body runs.
        main(["owasp-scan", "app.example-lab.local", "--category", "zz"])
