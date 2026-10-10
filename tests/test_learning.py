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
