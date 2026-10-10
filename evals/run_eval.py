"""Regression gate for the agent's self-growth changes.

Run against your own lab targets (configured in evals/targets.yaml,
pointed at your own scope.yaml with those lab hosts allow-listed) before
merging any change to prompts, tools, or knowledge. A change that drops the
pass rate should not merge.

    python -m evals.run_eval

Exits non-zero if any case fails, so it's a natural CI gate.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

from security_agent.config import load_config
from security_agent.loop import SecurityAgent

EVALS_DIR = Path(__file__).resolve().parent


def run() -> int:
    cases_file = EVALS_DIR / "targets.yaml"
    cases = yaml.safe_load(cases_file.read_text(encoding="utf-8")).get("cases", [])

    if not cases:
        print("No eval cases defined; nothing to gate on.")
        return 0

    config = load_config()
    config.require_human_approval_default = False  # non-interactive CI run

    failures = []
    for case in cases:
        print(f"\n=== Eval case: {case['name']} ===")
        try:
            agent = SecurityAgent(config=config)
            report = agent.run(case["objective"])
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR running case '{case['name']}': {exc}")
            failures.append(case["name"])
            continue

        text = report.render().lower()
        missing = [f for f in case.get("expected_findings", []) if f.lower() not in text]
        if missing:
            print(f"FAIL '{case['name']}': missing expected content {missing}")
            failures.append(case["name"])
        else:
            print(f"PASS '{case['name']}'")

    print(f"\n{len(cases) - len(failures)}/{len(cases)} eval cases passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run())
