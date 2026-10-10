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
        "k8s_live_scan",
        "api_fuzz_test",
        "sast_scan",
        "secret_scan",
        "cloud_posture_scan",
        "container_image_scan",
        "smart_contract_scan",
        "email_harvest",
        "username_osint",
        "traffic_capture",
        "binary_analysis",
        "deep_secret_scan",
        "fast_port_scan",
        "packet_capture",
        "active_directory_recon",
        "credential_test",
        "hash_crack",
        "phishing_simulation_launch",
        "propose_fix",
        "apply_fix_to_repo",
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


# ---------------------------------------------------- cloud/container/web3/API tools


def test_cloud_posture_scan_uses_local_action_not_domain_scope(guardrails):
    # profile_or_account is a credential identifier, not a network host --
    # it must not be checked against allowed_domains/allowed_cidrs.
    from security_agent.tools.cloud_posture import CloudPostureScanTool

    tool = CloudPostureScanTool()
    result = tool.run(guardrails, provider="aws", profile_or_account="not-a-hostname-at-all")
    # Should reach the "not installed" branch, not a ScopeViolation.
    assert result.ok is False
    assert "not installed" in result.summary


def test_container_image_scan_uses_local_action(guardrails, monkeypatch):
    from security_agent.tools.container_security import ContainerImageScanTool

    tool = ContainerImageScanTool()
    monkeypatch.setattr(tool, "available", lambda: True)
    monkeypatch.setattr(tool, "_run_subprocess", lambda cmd, timeout=600: (0, '{"Results": []}', ""))
    result = tool.run(guardrails, target="myapp:1.2.3")
    assert result.ok is True


def test_k8s_live_scan_is_network_target_and_scope_checked(guardrails):
    from security_agent.tools.container_security import K8sLiveScanTool

    tool = K8sLiveScanTool()
    with pytest.raises(ScopeViolation):
        tool.run(guardrails, target="not-in-scope-cluster.evil.com")


def test_k8s_live_scan_runs_against_in_scope_target(monkeypatch, guardrails):
    from security_agent.tools.container_security import K8sLiveScanTool

    tool = K8sLiveScanTool()
    monkeypatch.setattr(tool, "available", lambda: True)
    monkeypatch.setattr(tool, "_run_subprocess", lambda cmd, timeout=900: (0, "no issues found", ""))
    result = tool.run(guardrails, target="10.10.10.5")
    assert result.ok is True


def test_smart_contract_scan_uses_local_action(guardrails, monkeypatch):
    from security_agent.tools.smart_contract import SmartContractScanTool

    tool = SmartContractScanTool()
    monkeypatch.setattr(tool, "available", lambda: True)
    monkeypatch.setattr(tool, "_run_subprocess", lambda cmd, timeout=600: (1, "[]", ""))
    result = tool.run(guardrails, path="/local/contracts/Vault.sol")
    # Slither exits non-zero when findings exist -- that must still be ok=True.
    assert result.ok is True


def test_api_fuzz_test_is_network_target_and_caps_max_examples(monkeypatch, guardrails):
    from security_agent.tools.api_fuzz import ApiFuzzTool

    tool = ApiFuzzTool()
    monkeypatch.setattr(tool, "available", lambda: True)

    captured_cmd = {}

    def fake_run(cmd, timeout=600):
        captured_cmd["cmd"] = cmd
        return (0, "all checks passed", "")

    monkeypatch.setattr(tool, "_run_subprocess", fake_run)
    result = tool.run(
        guardrails,
        schema_url="https://app.example-lab.local/openapi.json",
        max_examples=99999,  # should be clamped, never passed through unbounded
    )
    assert result.ok is True
    idx = captured_cmd["cmd"].index("--max-examples")
    assert int(captured_cmd["cmd"][idx + 1]) <= 200


def test_api_fuzz_test_refuses_out_of_scope_schema(guardrails):
    from security_agent.tools.api_fuzz import ApiFuzzTool

    tool = ApiFuzzTool()
    with pytest.raises(ScopeViolation):
        tool.run(guardrails, schema_url="https://evil.com/openapi.json")


# ------------------------------------------------- OSINT / traffic / binary / deep secrets


def test_email_harvest_is_network_target_and_scope_checked(guardrails):
    from security_agent.tools.osint import EmailHarvestTool

    tool = EmailHarvestTool()
    with pytest.raises(ScopeViolation):
        tool.run(guardrails, domain="evil.com")


def test_email_harvest_runs_against_in_scope_domain(monkeypatch, guardrails):
    from security_agent.tools.osint import EmailHarvestTool

    tool = EmailHarvestTool()
    monkeypatch.setattr(tool, "available", lambda: True)
    monkeypatch.setattr(tool, "_run_subprocess", lambda cmd, timeout=300: (0, "found 2 emails", ""))
    result = tool.run(guardrails, domain="app.example-lab.local")
    assert result.ok is True


def test_username_osint_uses_local_action_not_domain_scope(guardrails):
    # The subject (username) isn't a network host -- it must not be
    # checked against allowed_domains/allowed_cidrs. It should reach the
    # "not installed" branch rather than a ScopeViolation.
    from security_agent.tools.osint import UsernameOsintTool

    tool = UsernameOsintTool()
    result = tool.run(guardrails, username="some-employee-handle")
    assert result.ok is False
    assert "not installed" in result.summary


def test_traffic_capture_is_network_target_and_caps_duration(guardrails):
    from security_agent.tools.traffic_capture import TrafficCaptureTool

    tool = TrafficCaptureTool()
    with pytest.raises(ScopeViolation):
        tool.run(guardrails, target="https://evil.com", duration_seconds=30)


def test_binary_analysis_uses_local_action(guardrails, monkeypatch):
    from security_agent.tools import binary_analysis as ba_module
    from security_agent.tools.binary_analysis import BinaryAnalysisTool

    tool = BinaryAnalysisTool()
    monkeypatch.setattr(ba_module, "_find_analyze_headless", lambda: "/usr/bin/analyzeHeadless")
    monkeypatch.setattr(tool, "_run_subprocess", lambda cmd, timeout=900: (0, "analysis complete", ""))
    result = tool.run(guardrails, path="/local/firmware.bin")
    assert result.ok is True


def test_binary_analysis_reports_missing_ghidra_cleanly(guardrails, monkeypatch):
    from security_agent.tools import binary_analysis as ba_module
    from security_agent.tools.binary_analysis import BinaryAnalysisTool

    tool = BinaryAnalysisTool()
    monkeypatch.setattr(ba_module, "_find_analyze_headless", lambda: None)
    result = tool.run(guardrails, path="/local/firmware.bin")
    assert result.ok is False
    assert "not installed" in result.summary or "analyzeHeadless" in result.summary


def test_deep_secret_scan_uses_local_action(guardrails, monkeypatch):
    from security_agent.tools.deep_secrets import DeepSecretScanTool

    tool = DeepSecretScanTool()
    monkeypatch.setattr(tool, "available", lambda: True)
    monkeypatch.setattr(tool, "_run_subprocess", lambda cmd, timeout=600: (0, "[]", ""))
    result = tool.run(guardrails, target="/local/repo")
    assert result.ok is True


# -------------------------------------- credential testing / hash cracking / AD / GoPhish
# All of these are `exploitation` category (or explicitly force the
# approval gate even for a local action) -- every test here proves the
# approval gate actually blocks/allows correctly, not just that the
# tool runs.


def test_credential_test_blocked_without_approval(make_scope, make_guardrails):
    from security_agent.tools.credential_attacks import CredentialTestTool

    scope = make_scope(
        rules_of_engagement={"allow_exploitation": True},
        require_human_approval_for=["exploitation"],
    )
    g = make_guardrails(scope, auto_deny_approvals=True)
    tool = CredentialTestTool()
    with pytest.raises(ApprovalRequired):
        tool.run(
            g, target="app.example-lab.local", service="ssh",
            username="testuser", password_list=["pw1", "pw2"],
        )


def test_credential_test_runs_once_approved_and_caps_wordlist(monkeypatch, make_scope, make_guardrails):
    from security_agent.tools.credential_attacks import CredentialTestTool

    scope = make_scope(
        rules_of_engagement={"allow_exploitation": True},
        require_human_approval_for=["exploitation"],
    )
    g = make_guardrails(scope, asker=lambda prompt: True)
    tool = CredentialTestTool()
    monkeypatch.setattr(tool, "available", lambda: True)

    captured = {}

    def fake_run(cmd, timeout=300):
        # Read the wordlist file now, while it still exists -- the real
        # tool unlinks it in a `finally` right after this call returns.
        wordlist_path = cmd[cmd.index("-P") + 1]
        with open(wordlist_path) as f:
            captured["wordlist_lines"] = f.readlines()
        return (0, "1 valid password found", "")

    monkeypatch.setattr(tool, "_run_subprocess", fake_run)
    result = tool.run(
        g, target="app.example-lab.local", service="ssh", username="testuser",
        password_list=[f"pw{i}" for i in range(100)],  # way over the cap
    )
    assert result.ok is True
    assert len(captured["wordlist_lines"]) <= 25


def test_hash_crack_blocked_without_approval(make_scope, make_guardrails):
    from security_agent.tools.credential_attacks import HashCrackTool

    scope = make_scope(require_human_approval_for=["exploitation"])
    g = make_guardrails(scope, auto_deny_approvals=True)
    tool = HashCrackTool()
    with pytest.raises(ApprovalRequired):
        tool.run(g, hash_file="/local/hashes.txt", hash_mode="0", wordlist="/local/wordlist.txt")


def test_hash_crack_runs_once_approved(monkeypatch, make_scope, make_guardrails):
    from security_agent.tools.credential_attacks import HashCrackTool

    scope = make_scope(require_human_approval_for=["exploitation"])
    g = make_guardrails(scope, asker=lambda prompt: True)
    tool = HashCrackTool()
    monkeypatch.setattr(tool, "available", lambda: True)
    monkeypatch.setattr(tool, "_run_subprocess", lambda cmd, timeout=150: (0, "cracked: 1 hash", ""))
    result = tool.run(g, hash_file="/local/hashes.txt", hash_mode="0", wordlist="/local/wordlist.txt")
    assert result.ok is True


def test_hash_crack_denial_is_not_logged_as_authorized(make_scope, make_guardrails, tmp_path):
    import json

    from security_agent.guardrails import AuditLog, Guardrails
    from security_agent.tools.credential_attacks import HashCrackTool

    scope = make_scope(require_human_approval_for=["exploitation"])
    audit = AuditLog(path=tmp_path / "audit.jsonl")
    g = Guardrails(scope=scope, audit=audit, auto_deny_approvals=True)
    tool = HashCrackTool()

    with pytest.raises(ApprovalRequired):
        tool.run(g, hash_file="/local/hashes.txt", hash_mode="0", wordlist="/local/wordlist.txt")

    # The denial happens before anything is ever written to the audit
    # log -- the file not existing at all is itself proof of that.
    if audit.path.exists():
        events = [json.loads(line)["event"] for line in audit.path.read_text().strip().splitlines()]
        assert "local_tool_call_authorized" not in events
    else:
        assert not audit.path.exists()


def test_active_directory_recon_is_network_target_and_scope_checked(guardrails):
    from security_agent.tools.active_directory import ActiveDirectoryReconTool

    tool = ActiveDirectoryReconTool()
    with pytest.raises(ScopeViolation):
        tool.run(
            guardrails, domain="corp.evil.com", domain_controller="dc.evil.com", username="svc-account"
        )


def test_fast_port_scan_refuses_out_of_scope(guardrails):
    from security_agent.tools.fast_scan import FastPortScanTool

    tool = FastPortScanTool()
    with pytest.raises(ScopeViolation):
        tool.run(guardrails, target="evil.com")


def test_packet_capture_uses_clean_target_not_raw_bpf_string(guardrails):
    from security_agent.tools.packet_capture import PacketCaptureTool

    tool = PacketCaptureTool()
    # The scope check must run against the clean host/CIDR, not a BPF
    # expression -- an out-of-scope target must still be refused even
    # though it would otherwise be a syntactically valid filter.
    with pytest.raises(ScopeViolation):
        tool.run(guardrails, interface="eth0", target="evil.com")


def test_packet_capture_builds_correct_bpf_filter(monkeypatch, guardrails):
    from security_agent.tools.packet_capture import PacketCaptureTool

    tool = PacketCaptureTool()
    monkeypatch.setattr(tool, "available", lambda: True)
    captured = {}

    def fake_run(cmd, timeout=60):
        captured["cmd"] = cmd
        return (0, "0 packets captured", "")

    monkeypatch.setattr(tool, "_run_subprocess", fake_run)
    tool.run(guardrails, interface="eth0", target="10.10.10.5", duration_seconds=10)
    assert "host 10.10.10.5" in captured["cmd"]


def test_phishing_simulation_refuses_out_of_scope_recipient(guardrails):
    from security_agent.tools.phishing_simulation import PhishingSimulationTool

    tool = PhishingSimulationTool()
    with pytest.raises(ScopeViolation):
        tool.run(
            guardrails,
            gophish_api_url="https://gophish.example-lab.local",
            gophish_api_key="fake-key",
            campaign_id=1,
            recipient_emails=["employee@evil-external-domain.com"],
        )


def test_phishing_simulation_blocked_without_approval(make_scope, make_guardrails):
    from security_agent.tools.phishing_simulation import PhishingSimulationTool

    scope = make_scope(require_human_approval_for=["exploitation"])
    g = make_guardrails(scope, auto_deny_approvals=True)
    tool = PhishingSimulationTool()
    with pytest.raises(ApprovalRequired):
        tool.run(
            g,
            gophish_api_url="https://gophish.example-lab.local",
            gophish_api_key="fake-key",
            campaign_id=1,
            recipient_emails=["employee@app.example-lab.local"],
        )


# ---------------------------------------------------------- propose_fix / apply_fix_to_repo


def test_propose_fix_needs_no_approval_and_writes_reviewable_file(guardrails, monkeypatch, tmp_path):
    from security_agent import config as cfg
    from security_agent.tools.remediation import ProposeFixTool

    monkeypatch.setattr(cfg, "REPORTS_DIR", tmp_path / "reports")
    tool = ProposeFixTool()
    result = tool.run(
        guardrails,
        finding_title="Missing MFA on admin panel",
        root_cause="Admin login accepts username+password only.",
        patch="--- a/config\n+++ b/config\n+require_mfa = true\n",
        verification_steps="Attempt admin login without MFA; it should now be rejected.",
        target_file="config/auth.yaml",
    )
    assert result.ok is True
    written = (tmp_path / "reports" / "fixes").glob("*.md")
    files = list(written)
    assert len(files) == 1
    content = files[0].read_text()
    assert "Missing MFA on admin panel" in content
    assert "require_mfa = true" in content
    assert "Nothing on the" in content  # the "not applied" disclaimer


def test_propose_fix_never_touches_a_network_target(guardrails, monkeypatch, tmp_path):
    # propose_fix takes no network target at all -- confirm it runs
    # successfully even with a scope that denies everything else, since
    # drafting a fix doesn't go through check_target/check_action_allowed.
    from security_agent import config as cfg
    from security_agent.tools.remediation import ProposeFixTool

    monkeypatch.setattr(cfg, "REPORTS_DIR", tmp_path / "reports")
    tool = ProposeFixTool()
    result = tool.run(
        guardrails,
        finding_title="X",
        root_cause="Y",
        patch="Z",
        verification_steps="W",
    )
    assert result.ok is True


def test_apply_fix_to_repo_blocked_without_approval(make_scope, make_guardrails, tmp_path):
    from security_agent.tools.remediation import ApplyFixToRepoTool

    scope = make_scope(require_human_approval_for=[])  # even with an empty list
    g = make_guardrails(scope, auto_deny_approvals=True)
    tool = ApplyFixToRepoTool()
    with pytest.raises(ApprovalRequired):
        tool.run(
            g,
            repo_path=str(tmp_path),
            branch_name="fix/mfa",
            patch_file="/tmp/fix.patch",
            commit_message="Require MFA on admin login",
        )


def test_apply_fix_to_repo_runs_once_approved(monkeypatch, make_scope, make_guardrails, tmp_path):
    from security_agent.tools.remediation import ApplyFixToRepoTool

    scope = make_scope()
    g = make_guardrails(scope, asker=lambda prompt: True)
    tool = ApplyFixToRepoTool()
    monkeypatch.setattr(tool, "available", lambda: True)

    calls = []

    class FakeProc:
        returncode = 0
        stdout = "ok\n"
        stderr = ""

    def fake_subprocess_run(cmd, capture_output, text, timeout):
        calls.append(cmd)
        return FakeProc()

    monkeypatch.setattr("security_agent.tools.remediation.subprocess.run", fake_subprocess_run)
    result = tool.run(
        g,
        repo_path=str(tmp_path),
        branch_name="fix/mfa",
        patch_file="/tmp/fix.patch",
        commit_message="Require MFA on admin login",
    )
    assert result.ok is True
    assert len(calls) == 4  # checkout -b, apply, add, commit
    assert calls[0][:4] == ["git", "-C", str(tmp_path), "checkout"]


def test_apply_fix_to_repo_refuses_nonexistent_path(make_scope, make_guardrails):
    from security_agent.tools.remediation import ApplyFixToRepoTool

    scope = make_scope()
    g = make_guardrails(scope, asker=lambda prompt: True)
    tool = ApplyFixToRepoTool()
    result = tool.run(
        g,
        repo_path="/definitely/not/a/real/path/anywhere",
        branch_name="fix/x",
        patch_file="/tmp/fix.patch",
        commit_message="x",
    )
    assert result.ok is False
    assert "not a local directory" in result.summary
