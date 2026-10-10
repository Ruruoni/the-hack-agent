"""Tests for security_agent/memory.py: playbooks load in full and in
order; growth notes load most-recent-first within a budget; README.md
never leaks into growth notes.
"""
from __future__ import annotations

import time
from pathlib import Path

from security_agent.memory import KnowledgeBase


def _make_kb(tmp_path: Path) -> KnowledgeBase:
    return KnowledgeBase(root=tmp_path / "knowledge")


def test_load_playbooks_empty_when_none_exist(tmp_path):
    kb = _make_kb(tmp_path)
    assert kb.load_playbooks() == ""


def test_load_playbooks_loads_all_in_sorted_order(tmp_path):
    kb = _make_kb(tmp_path)
    (kb.playbooks_dir / "b01-later.md").write_text("later content")
    (kb.playbooks_dir / "00-first.md").write_text("first content")
    (kb.playbooks_dir / "a05-middle.md").write_text("middle content")

    text = kb.load_playbooks()
    assert text.index("00-first.md") < text.index("a05-middle.md") < text.index("b01-later.md")
    assert "first content" in text
    assert "middle content" in text
    assert "later content" in text


def test_load_playbooks_is_never_truncated_by_a_budget(tmp_path):
    kb = _make_kb(tmp_path)
    big = "x" * 50_000
    (kb.playbooks_dir / "00-big.md").write_text(big)
    assert big in kb.load_playbooks()


def test_write_note_creates_timestamped_file(tmp_path):
    kb = _make_kb(tmp_path)
    path = kb.write_note("My Finding", "some body text")
    assert path.exists()
    assert "my-finding" in path.name
    content = path.read_text()
    assert "My Finding" in content
    assert "some body text" in content


def test_load_growth_notes_excludes_readme(tmp_path):
    kb = _make_kb(tmp_path)
    (kb.root / "README.md").write_text("this is just documentation, not a note")
    kb.write_note("real finding", "actual content")

    notes = kb.load_growth_notes()
    assert "actual content" in notes
    assert "just documentation" not in notes


def test_load_growth_notes_most_recent_first(tmp_path):
    kb = _make_kb(tmp_path)
    kb.write_note("older", "older body")
    time.sleep(0.01)
    kb.write_note("newer", "newer body")

    notes = kb.load_growth_notes()
    assert notes.index("newer body") < notes.index("older body")


def test_load_growth_notes_respects_char_budget(tmp_path):
    kb = _make_kb(tmp_path)
    path_one = kb.write_note("one", "a" * 100)
    time.sleep(0.01)
    path_two = kb.write_note("two", "b" * 100)

    # Each note's full on-disk size (header + body) is what counts against
    # the budget, not just the raw body passed to write_note -- budget
    # tight enough for exactly one full note file, not both.
    one_size = len(path_one.read_text())
    two_size = len(path_two.read_text())
    budget = two_size + 10  # fits the most recent note, not both

    notes = kb.load_growth_notes(max_chars=budget)
    assert "b" * 100 in notes
    assert "a" * 100 not in notes
    assert budget < one_size + two_size  # sanity: the budget really is tight


def test_load_all_combines_playbooks_and_growth_notes(tmp_path):
    kb = _make_kb(tmp_path)
    (kb.playbooks_dir / "00-methodology.md").write_text("the methodology")
    kb.write_note("a run", "what happened")

    combined = kb.load_all()
    assert "the methodology" in combined
    assert "what happened" in combined
    assert combined.index("the methodology") < combined.index("what happened")


def test_load_all_with_nothing_present_returns_empty_string(tmp_path):
    kb = _make_kb(tmp_path)
    assert kb.load_all() == ""
