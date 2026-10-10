"""Tests for security_agent/learning.py: the self-learn/staging path.

Every test here proves the actual safety property this module exists
for: reading/drafting never executes anything from the source, and a
staged draft is never auto-registered into the live tool registry.
No real network clone happens -- learn_from_repo is pointed at a real
local git repo created in a temp dir, so this stays fast and offline.
"""
from __future__ import annotations

import json
import subprocess

import pytest

from security_agent.config import AgentConfig
from security_agent.guardrails import AuditLog
from security_agent.learning import LearningAgent
from security_agent.memory import KnowledgeBase
from security_agent.tools import build_default_registry


class FakeResponse:
    def __init__(self, content: str):
        self.content = content
        self.tool_calls = []
        self.usage_tokens = 5


class ScriptedProvider:
    def __init__(self, payload: dict):
        self.payload = payload
        self.calls = 0

    def chat(self, messages, tools):
        self.calls += 1
        return FakeResponse(json.dumps(self.payload))


@pytest.fixture
def local_repo(tmp_path):
    repo_dir = tmp_path / "fake-repo"
    repo_dir.mkdir()
    (repo_dir / "README.md").write_text(
        "# Tiny Tool\nA small CLI that enumerates subdomains from certificate transparency logs."
    )
    subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo_dir, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t.com", "-c", "user.name=t", "commit", "-q", "-m", "init"],
        cwd=repo_dir, check=True,
    )
    return repo_dir


@pytest.fixture
def learning_agent(tmp_path, monkeypatch):
    from security_agent import config as cfg

    monkeypatch.setattr(cfg, "TOOLS_STAGING_DIR", tmp_path / "tools_staging")
    monkeypatch.setattr(cfg, "PLAYBOOKS_STAGING_DIR", tmp_path / "playbooks_staging")

    def _make(payload: dict):
        return LearningAgent(
            config=AgentConfig(),
            provider=ScriptedProvider(payload),
            audit=AuditLog(path=tmp_path / "audit.jsonl"),
            knowledge=KnowledgeBase(root=tmp_path / "knowledge"),
        )

    return _make


def test_learn_from_repo_accept_stages_tool_and_playbook(local_repo, learning_agent):
    agent = learning_agent(
        {
            "decision": "accept",
            "reasoning": "Single-purpose passive recon tool, same shape as subdomain_enum.",
            "tool_name": "Tiny Subdomain Tool!!",
            "action_category": "passive_recon",
            "tool_code": "class TinySubdomainTool:\n    name = 'tiny_subdomain_tool'\n",
            "playbook_markdown": "## Tiny Subdomain Tool\nPassive CT-log enumeration.",
        }
    )
    report = agent.learn_from_repo(str(local_repo))

    assert report.decision == "accept"
    assert report.staged_tool_path is not None
    assert report.staged_tool_path.exists()
    assert report.staged_tool_path.suffix == ".draft"
    assert "TinySubdomainTool" in report.staged_tool_path.read_text()

    assert report.staged_playbook_path is not None
    assert report.staged_playbook_path.exists()


def test_learn_from_repo_decline_stages_nothing(local_repo, learning_agent):
    agent = learning_agent({"decision": "decline", "reasoning": "Catalogs a DDoS Attack Tools category."})
    report = agent.learn_from_repo(str(local_repo))

    assert report.decision == "decline"
    assert report.staged_tool_path is None
    assert report.staged_playbook_path is None


def test_learn_from_repo_never_registers_into_live_tool_registry(local_repo, learning_agent):
    # The actual safety property: no matter what gets staged, the live
    # registry used by SecurityAgent is completely unaffected.
    before = set(build_default_registry().names())
    agent = learning_agent(
        {
            "decision": "accept",
            "reasoning": "x",
            "tool_name": "some_new_tool",
            "action_category": "passive_recon",
            "tool_code": "class SomeNewTool:\n    name = 'some_new_tool'\n",
        }
    )
    agent.learn_from_repo(str(local_repo))
    after = set(build_default_registry().names())
    assert before == after
    assert "some_new_tool" not in after


def test_learn_from_repo_writes_a_knowledge_note_either_way(local_repo, learning_agent):
    agent = learning_agent({"decision": "decline", "reasoning": "nope"})
    report = agent.learn_from_repo(str(local_repo))
    assert report.knowledge_note_path is not None
    assert report.knowledge_note_path.exists()
    content = report.knowledge_note_path.read_text()
    assert str(local_repo) in content
    assert "decline" in content


def test_learn_from_repo_handles_unparseable_model_output(local_repo, learning_agent):
    agent = learning_agent({})  # payload irrelevant; override chat below
    agent.provider.chat = lambda messages, tools: FakeResponse("not json at all, sorry")
    report = agent.learn_from_repo(str(local_repo))
    assert report.decision == "error"


def test_learn_from_repo_handles_nonexistent_source_gracefully(learning_agent):
    agent = learning_agent({"decision": "decline", "reasoning": "n/a"})
    report = agent.learn_from_repo("/definitely/not/a/real/repo/path")
    # A failed clone still produces a report, never an unhandled exception.
    assert report.decision in ("error", "decline")


def test_learn_from_document_summarizes_text_file(tmp_path, learning_agent):
    doc = tmp_path / "notes.md"
    doc.write_text("# Login flow\nPassword field present, no CSRF token observed.")
    agent = learning_agent({})
    agent.provider.chat = lambda messages, tools: FakeResponse(
        "Describes a login flow; notes a missing CSRF token."
    )
    report = agent.learn_from_document(str(doc))
    assert report.decision == "summarized"
    assert "CSRF" in report.reasoning
    assert report.knowledge_note_path.exists()


def test_learn_from_document_refuses_missing_file(learning_agent):
    agent = learning_agent({})
    report = agent.learn_from_document("/definitely/not/a/real/file.md")
    assert report.decision == "error"
    assert "does not exist" in report.reasoning


def test_learn_from_document_refuses_binary_content_cleanly(tmp_path, learning_agent):
    doc = tmp_path / "binary.dat"
    doc.write_bytes(b"\x00\x01\x02\xff\xfe\xfd" * 100)
    agent = learning_agent({})
    report = agent.learn_from_document(str(doc))
    assert report.decision == "error"
    assert "multimodal" in report.reasoning.lower() or "binary" in report.reasoning.lower()


def test_learn_from_repo_writes_audit_trail(local_repo, learning_agent, tmp_path):
    agent = learning_agent({"decision": "decline", "reasoning": "nope"})
    agent.learn_from_repo(str(local_repo))

    audit_path = agent.audit.path
    assert audit_path.exists()
    events = [json.loads(line)["event"] for line in audit_path.read_text().strip().splitlines()]
    assert "learning_action_started" in events
    assert "learning_action_finished" in events


# ------------------------------------------------------------- learn_from_text


def test_learn_from_text_stages_playbook_addendum_when_worthwhile(learning_agent):
    agent = learning_agent(
        {
            "summary": "Describes IDOR via sequential numeric IDs in an API.",
            "worth_a_playbook_note": True,
            "playbook_addendum": "### Sequential-ID IDOR variant\nCheck for predictable numeric IDs.",
            "suggested_playbook": "a01-broken-access-control.md",
        }
    )
    report = agent.learn_from_text(
        "A user noticed /api/orders/1042 could be changed to /api/orders/1041.", label="forum-post"
    )
    assert report.decision == "summarized"
    assert report.staged_playbook_path is not None
    content = report.staged_playbook_path.read_text()
    assert "Sequential-ID IDOR" in content
    assert "a01-broken-access-control.md" in content


def test_learn_from_text_stages_nothing_when_not_worthwhile(learning_agent):
    agent = learning_agent({"summary": "Just a greeting, nothing security-relevant.", "worth_a_playbook_note": False})
    report = agent.learn_from_text("hello there", label="chat-message")
    assert report.decision == "summarized"
    assert report.staged_playbook_path is None


def test_learn_from_text_falls_back_to_raw_summary_on_unparseable_output(learning_agent):
    agent = learning_agent({})
    agent.provider.chat = lambda messages, tools: type(
        "R", (), {"content": "This is just plain prose, not JSON.", "tool_calls": [], "usage_tokens": 1}
    )()
    report = agent.learn_from_text("some content", label="x")
    assert report.decision == "summarized"
    assert "plain prose" in report.reasoning
    assert report.staged_playbook_path is None


def test_learn_from_text_never_registers_a_new_tool(learning_agent):
    # learn_from_text/url/document never draft executable tool code,
    # only playbook notes -- confirm no tool-staging side effect at all.
    agent = learning_agent(
        {
            "summary": "x",
            "worth_a_playbook_note": True,
            "playbook_addendum": "### Note\nSome technique.",
            "suggested_playbook": "new",
        }
    )
    report = agent.learn_from_text("content", label="x")
    assert report.staged_tool_path is None


# -------------------------------------------------------------- learn_from_url


def test_learn_from_url_strips_html_and_stages_note(learning_agent, monkeypatch):
    html = (
        "<html><head><script>alert(1)</script></head>"
        "<body><h1>SSRF Write-up</h1><p>Found via the PDF export feature.</p></body></html>"
    )

    class FakeResp:
        text = html
        headers = {"content-type": "text/html"}

        def raise_for_status(self):
            pass

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, headers=None):
            return FakeResp()

    monkeypatch.setattr("security_agent.learning.httpx.Client", lambda timeout=30, follow_redirects=True: FakeClient())

    agent = learning_agent(
        {
            "summary": "SSRF via PDF export.",
            "worth_a_playbook_note": True,
            "playbook_addendum": "### PDF-export SSRF\nTest export features against metadata endpoints.",
            "suggested_playbook": "a10-ssrf.md",
        }
    )
    report = agent.learn_from_url("http://example.test/writeup")
    assert report.decision == "summarized"
    assert report.staged_playbook_path is not None
    assert "alert(1)" not in report.staged_playbook_path.read_text()


def test_learn_from_url_handles_fetch_failure_gracefully(learning_agent, monkeypatch):
    def _raise(*a, **kw):
        raise ConnectionError("simulated network failure")

    monkeypatch.setattr("security_agent.learning.httpx.Client", _raise)
    agent = learning_agent({})
    report = agent.learn_from_url("http://unreachable.test/page")
    assert report.decision == "error"


# ---------------------------------------------------------------- consolidate


def test_consolidate_with_no_notes_yet_errors_cleanly(learning_agent):
    agent = learning_agent({})
    report = agent.consolidate()
    assert report.decision == "error"
    assert "No growth notes" in report.reasoning


def test_consolidate_synthesizes_and_stages_addendum(learning_agent):
    agent = learning_agent(
        {
            "digest": "IDOR via sequential IDs recurred across runs.",
            "worth_a_playbook_update": True,
            "playbook_addendum": "### Standing check\nAlways try adjacent IDs.",
            "suggested_playbook": "a01-broken-access-control.md",
        }
    )
    agent.knowledge.write_note("run-1", "Found IDOR via sequential IDs on orders.")
    agent.knowledge.write_note("run-2", "Found IDOR via sequential IDs on invoices.")

    report = agent.consolidate()
    assert report.decision == "summarized"
    assert "recurred" in report.reasoning
    assert report.staged_playbook_path is not None
    assert "consolidated-" in report.staged_playbook_path.name


def test_consolidate_stages_nothing_when_not_worthwhile(learning_agent):
    agent = learning_agent({"digest": "Nothing notable recurs.", "worth_a_playbook_update": False})
    agent.knowledge.write_note("run-1", "A one-off finding, not a pattern.")
    report = agent.consolidate()
    assert report.decision == "summarized"
    assert report.staged_playbook_path is None


def test_consolidate_never_edits_a_live_playbook_file(learning_agent):
    # Confirm the real, loaded playbooks directory is untouched -- only
    # the staging directory ever receives a file.
    from security_agent.memory import KnowledgeBase as RealKB

    real_pb_dir = RealKB().playbooks_dir
    before = {p: p.read_text() for p in real_pb_dir.glob("*.md")}

    agent = learning_agent(
        {
            "digest": "x",
            "worth_a_playbook_update": True,
            "playbook_addendum": "### Should never land here directly\n",
            "suggested_playbook": "a01-broken-access-control.md",
        }
    )
    agent.knowledge.write_note("run-1", "finding")
    agent.consolidate()

    after = {p: p.read_text() for p in real_pb_dir.glob("*.md")}
    assert before == after
