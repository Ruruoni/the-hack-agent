"""CLI entrypoint.

    python -m security_agent.cli run "Enumerate subdomains of example-lab.local \
and check for exposed admin panels"

Refuses to run at all unless scope.yaml has authorized: true.
"""
from __future__ import annotations

import argparse
import logging
import sys

from .config import load_config
from .guardrails import Guardrails, ScopeViolation
from .loop import SecurityAgent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="security_agent")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run the agent with an objective.")
    run_p.add_argument("objective", help="Natural-language objective, scoped to targets in scope.yaml")
    run_p.add_argument("--non-interactive", action="store_true", help="Auto-deny gated approvals instead of prompting.")
    run_p.add_argument("-v", "--verbose", action="store_true")

    check_p = sub.add_parser("check-scope", help="Validate scope.yaml and exit.")
    check_p.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.command == "check-scope":
        try:
            g = Guardrails()
            g.scope.check_authorized()
        except ScopeViolation as exc:
            print(f"SCOPE INVALID: {exc}", file=sys.stderr)
            return 1
        print("scope.yaml is valid and authorized.")
        return 0

    if args.command == "run":
        config = load_config()
        config.require_human_approval_default = not args.non_interactive
        try:
            agent = SecurityAgent(config=config)
        except ScopeViolation as exc:
            print(f"REFUSING TO START: {exc}", file=sys.stderr)
            return 1

        report = agent.run(args.objective)
        print(report.render())
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
