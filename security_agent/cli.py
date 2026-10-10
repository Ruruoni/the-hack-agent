"""CLI entrypoint.

    python -m security_agent.cli run "Enumerate subdomains of example-lab.local \
and check for exposed admin panels"

    python -m security_agent.cli owasp-scan juice.example-lab.local
    python -m security_agent.cli owasp-scan juice.example-lab.local --category a03
    python -m security_agent.cli list-playbooks

Refuses to run at all unless scope.yaml has authorized: true.
"""
from __future__ import annotations

import argparse
import logging
import sys

from .config import load_config
from .guardrails import Guardrails, ScopeViolation
from .loop import SecurityAgent
from .memory import KnowledgeBase

OWASP_CATEGORIES = {
    "a01": "Broken Access Control",
    "a02": "Cryptographic Failures",
    "a03": "Injection",
    "a04": "Insecure Design",
    "a05": "Security Misconfiguration",
    "a06": "Vulnerable and Outdated Components",
    "a07": "Identification and Authentication Failures",
    "a08": "Software and Data Integrity Failures",
    "a09": "Security Logging and Monitoring Failures",
    "a10": "Server-Side Request Forgery (SSRF)",
}


def _build_owasp_objective(target: str, category: str | None) -> str:
    if category:
        key = category.lower()
        name = OWASP_CATEGORIES.get(key)
        if not name:
            raise ValueError(
                f"Unknown category '{category}'. Valid: {', '.join(OWASP_CATEGORIES)}"
            )
        return (
            f"Run the OWASP {key.upper()} ({name}) playbook against {target}, "
            f"following knowledge/playbooks/{key}-*.md and the phase order in "
            f"knowledge/playbooks/00-methodology.md. Report findings with "
            f"severity and remediation."
        )
    return (
        f"Run a full OWASP Top 10 (2021) assessment against {target}, following "
        f"the phase order in knowledge/playbooks/00-methodology.md: passive "
        f"recon, mapping, then each category playbook (a01 through a10) in "
        f"order. Stay within scope.yaml at every step. Report findings with "
        f"severity and remediation; propose exploitation steps but do not "
        f"assume approval."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="security_agent")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run the agent with a free-form objective.")
    run_p.add_argument("objective", help="Natural-language objective, scoped to targets in scope.yaml")
    run_p.add_argument("--non-interactive", action="store_true", help="Auto-deny gated approvals instead of prompting.")
    run_p.add_argument("-v", "--verbose", action="store_true")

    owasp_p = sub.add_parser(
        "owasp-scan", help="Run a ready-made OWASP Top 10 assessment (full, or one category)."
    )
    owasp_p.add_argument("target", help="In-scope host/domain/URL to assess.")
    owasp_p.add_argument(
        "--category", choices=sorted(OWASP_CATEGORIES), help="Limit to one OWASP category (default: all)."
    )
    owasp_p.add_argument("--non-interactive", action="store_true")
    owasp_p.add_argument("-v", "--verbose", action="store_true")

    list_p = sub.add_parser("list-playbooks", help="List the curated playbooks loaded into the agent.")

    check_p = sub.add_parser("check-scope", help="Validate scope.yaml and exit.")
    check_p.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.command == "list-playbooks":
        kb = KnowledgeBase()
        files = sorted(kb.playbooks_dir.glob("*.md"))
        if not files:
            print("No playbooks found in knowledge/playbooks/.")
            return 0
        for f in files:
            first_line = f.read_text(encoding="utf-8").splitlines()[0].lstrip("# ")
            print(f"{f.name:40s} {first_line}")
        return 0

    if args.command == "check-scope":
        try:
            g = Guardrails()
            g.scope.check_authorized()
        except ScopeViolation as exc:
            print(f"SCOPE INVALID: {exc}", file=sys.stderr)
            return 1
        print("scope.yaml is valid and authorized.")
        return 0

    if args.command in ("run", "owasp-scan"):
        config = load_config()
        config.require_human_approval_default = not args.non_interactive
        try:
            agent = SecurityAgent(config=config)
        except ScopeViolation as exc:
            print(f"REFUSING TO START: {exc}", file=sys.stderr)
            return 1

        if args.command == "owasp-scan":
            try:
                objective = _build_owasp_objective(args.target, args.category)
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 1
        else:
            objective = args.objective

        report = agent.run(objective)
        print(report.render())
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
