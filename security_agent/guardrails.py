"""Authorization and safety enforcement.

This module is the one place every tool call must pass through. It is
intentionally defensive: a model mistake, a bad plan, or a malicious prompt
reaching the agent cannot bypass it, because the checks are code, not
instructions the model is asked to follow.

Protect this file and `scope.yaml` with CODEOWNERS + branch protection so
the agent's own self-improvement PRs can never weaken them unreviewed.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from . import config as cfg


# Action categories that ALWAYS require human approval, regardless of
# what scope.yaml's require_human_approval_for says. A config file can
# add to the set of gated categories (e.g. adding "active_scanning" to
# require approval on every active scan too) but can never remove these
# -- they are not configuration, they're this agent's non-negotiable
# floor. Any tool using authorize_local_exploitation_action or
# authorize_write_action relies on this being unconditional.
ALWAYS_REQUIRE_APPROVAL = frozenset({"exploitation", "any_write_to_target"})


class ScopeViolation(RuntimeError):
    """Raised whenever an action would fall outside the authorized scope."""


class BudgetExceeded(RuntimeError):
    """Raised when a run-level budget cap (calls, time, tokens) is hit."""


class ApprovalRequired(RuntimeError):
    """Raised when an action needs a human 'approve' that hasn't happened."""


@dataclass
class Scope:
    authorized: bool
    authorized_by: str
    authorization_reference: str
    allowed_domains: list[str]
    allowed_cidrs: list[str]
    denied_domains: list[str]
    denied_cidrs: list[str]
    rules_of_engagement: dict[str, Any]
    budgets: dict[str, Any]
    require_human_approval_for: list[str]

    @classmethod
    def load(cls, path: Path = cfg.SCOPE_FILE) -> "Scope":
        if not path.exists():
            raise ScopeViolation(
                f"No scope.yaml found at {path}. Refusing to run without an "
                "explicit authorization scope."
            )
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        targets = raw.get("targets", {})
        return cls(
            authorized=bool(raw.get("authorized", False)),
            authorized_by=raw.get("authorized_by", ""),
            authorization_reference=raw.get("authorization_reference", ""),
            allowed_domains=targets.get("allowed_domains", []) or [],
            allowed_cidrs=targets.get("allowed_cidrs", []) or [],
            denied_domains=targets.get("denied_domains", []) or [],
            denied_cidrs=targets.get("denied_cidrs", []) or [],
            rules_of_engagement=raw.get("rules_of_engagement", {}) or {},
            budgets=raw.get("budgets", {}) or {},
            require_human_approval_for=raw.get("require_human_approval_for", []) or [],
        )

    def check_authorized(self) -> None:
        if not self.authorized:
            raise ScopeViolation(
                "scope.yaml sets authorized: false. A human must set "
                "authorized: true (with authorized_by and "
                "authorization_reference filled in) before any tool runs."
            )
        if not self.authorized_by or not self.authorization_reference:
            raise ScopeViolation(
                "scope.yaml is marked authorized but authorized_by / "
                "authorization_reference is empty. Refusing to run."
            )

    def _is_domain_allowed(self, host: str) -> bool:
        host = host.lower().strip(".")
        for pattern in self.denied_domains:
            if fnmatch.fnmatch(host, pattern.lower()):
                return False
        for pattern in self.allowed_domains:
            if fnmatch.fnmatch(host, pattern.lower()):
                return True
        return False

    def _is_ip_allowed(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        for cidr in self.denied_cidrs:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return False
        for cidr in self.allowed_cidrs:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        return False

    def check_target(self, target: str) -> None:
        """Refuse any target (hostname, URL, or IP/CIDR) not explicitly
        allow-listed. Called before every single tool execution.
        """
        self.check_authorized()
        host = target
        for prefix in ("http://", "https://"):
            if host.startswith(prefix):
                host = host[len(prefix):]
        host = host.split("/")[0].split(":")[0]

        allowed = self._is_domain_allowed(host) or self._is_ip_allowed(host)
        if not allowed:
            raise ScopeViolation(
                f"Target '{target}' is not in scope.yaml's allowed_domains "
                f"or allowed_cidrs. Refusing to touch it."
            )

    def check_action_allowed(self, action_category: str) -> None:
        """action_category in {'passive_recon','active_scanning',
        'exploitation','destructive_actions','denial_of_service'}"""
        key = f"allow_{action_category}"
        if not self.rules_of_engagement.get(key, False):
            raise ScopeViolation(
                f"Action category '{action_category}' is not permitted by "
                f"scope.yaml (rules_of_engagement.{key} is false)."
            )

    def needs_human_approval(self, action_category: str) -> bool:
        return (
            action_category in ALWAYS_REQUIRE_APPROVAL
            or action_category in self.require_human_approval_for
        )


class AuditLog:
    """Append-only JSONL log of every tool call the agent makes, so every
    run is fully reconstructable after the fact.
    """

    def __init__(self, path: Path = cfg.AUDIT_LOG_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: str, **fields: Any) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")


class BudgetTracker:
    """Enforces the run-level caps in scope.yaml's `budgets` block, and the
    requests-per-second limit in `rules_of_engagement`, independent of
    whether the model "remembers" to stop itself.
    """

    def __init__(self, scope: Scope):
        self.scope = scope
        self.tool_calls = 0
        self.llm_tokens = 0
        self.started_at = time.monotonic()
        self._last_request_ts: dict[str, float] = {}

    def note_tool_call(self) -> None:
        self.tool_calls += 1
        max_calls = self.scope.budgets.get("max_tool_calls_per_run")
        if max_calls and self.tool_calls > max_calls:
            raise BudgetExceeded(f"max_tool_calls_per_run ({max_calls}) exceeded.")

    def note_llm_tokens(self, n: int) -> None:
        self.llm_tokens += n
        max_tokens = self.scope.budgets.get("max_llm_tokens_per_run")
        if max_tokens and self.llm_tokens > max_tokens:
            raise BudgetExceeded(f"max_llm_tokens_per_run ({max_tokens}) exceeded.")

    def check_runtime(self) -> None:
        max_minutes = self.scope.budgets.get("max_runtime_minutes")
        elapsed_minutes = (time.monotonic() - self.started_at) / 60
        if max_minutes and elapsed_minutes > max_minutes:
            raise BudgetExceeded(f"max_runtime_minutes ({max_minutes}) exceeded.")

    def throttle(self, target: str) -> None:
        """Simple per-target rate limit honoring max_requests_per_second."""
        rps = self.scope.rules_of_engagement.get("max_requests_per_second", 5)
        if not rps or rps <= 0:
            return
        min_interval = 1.0 / rps
        last = self._last_request_ts.get(target, 0.0)
        wait = min_interval - (time.monotonic() - last)
        if wait > 0:
            time.sleep(wait)
        self._last_request_ts[target] = time.monotonic()


class ApprovalGate:
    """Human-in-the-loop gate for anything scope.yaml marks as requiring
    approval. CLI implementation blocks on stdin; wire a different
    `asker` callable (e.g. a Slack/GitHub prompt) for non-interactive runs.
    """

    def __init__(self, scope: Scope, asker=None, auto_deny: bool = False):
        self.scope = scope
        self.auto_deny = auto_deny
        self._asker = asker or self._cli_asker

    @staticmethod
    def _cli_asker(prompt: str) -> bool:
        answer = input(f"\n[APPROVAL REQUIRED] {prompt}\nApprove? [y/N]: ")
        return answer.strip().lower() in ("y", "yes")

    def require(self, action_category: str, description: str) -> None:
        if not self.scope.needs_human_approval(action_category):
            return
        if self.auto_deny:
            raise ApprovalRequired(
                f"'{description}' requires human approval and this run is "
                "non-interactive (auto_deny=True)."
            )
        approved = self._asker(f"{action_category}: {description}")
        if not approved:
            raise ApprovalRequired(f"Human denied approval for: {description}")


class Guardrails:
    """Single object the agent loop and every tool hold a reference to."""

    def __init__(
        self,
        asker=None,
        auto_deny_approvals: bool = False,
        scope: "Scope | None" = None,
        audit: "AuditLog | None" = None,
    ):
        # scope/audit are injectable so tests can exercise real Guardrails
        # logic against a throwaway Scope/AuditLog instead of monkeypatching
        # Scope.load or touching the real scope.yaml / reports/audit.jsonl.
        self.scope = scope or Scope.load()
        # Fail fast at construction, not only on the first tool call: an
        # unauthorized scope.yaml should refuse before the agent loop even
        # starts talking to a model, not silently wait until something
        # tries to act.
        self.scope.check_authorized()
        self.audit = audit or AuditLog()
        self.budget = BudgetTracker(self.scope)
        self.approval = ApprovalGate(self.scope, asker=asker, auto_deny=auto_deny_approvals)

    def authorize_tool_call(
        self, tool_name: str, target: str, action_category: str, description: str
    ) -> None:
        """Call this before *every* tool execution. Raises on any violation."""
        self.budget.check_runtime()
        self.budget.note_tool_call()
        self.scope.check_target(target)
        self.scope.check_action_allowed(action_category)
        self.approval.require(action_category, description)
        self.budget.throttle(target)
        self.audit.record(
            "tool_call_authorized",
            tool=tool_name,
            target=target,
            category=action_category,
            description=description,
        )

    def authorize_local_action(self, tool_name: str, path: str, description: str) -> None:
        """For tools that only read local files (SAST, secret scanning on
        this repo's own checkout) — no external target, so the domain/CIDR
        allow-list doesn't apply, but budgets/audit still do.
        """
        self.budget.check_runtime()
        self.budget.note_tool_call()
        self.audit.record(
            "local_tool_call_authorized", tool=tool_name, path=path, description=description
        )

    def authorize_local_exploitation_action(self, tool_name: str, path: str, description: str) -> None:
        """Like `authorize_local_action`, but for local tools whose own
        category is `exploitation` (e.g. offline hash cracking on data
        already extracted via a separately-approved step) — the human
        approval check runs *before* anything is logged as authorized,
        so a denial never gets recorded as if the action had proceeded.
        """
        self.budget.check_runtime()
        self.approval.require("exploitation", description)
        self.budget.note_tool_call()
        self.audit.record(
            "local_tool_call_authorized", tool=tool_name, path=path, description=description
        )

    def authorize_write_action(self, tool_name: str, path: str, description: str) -> None:
        """For tools that write to a real codebase/system rather than
        only reading it (e.g. applying a generated fix) — always forces
        human approval under the `any_write_to_target` category,
        unconditionally, the same way exploitation-hardcoded tools do.
        Drafting/proposing a fix (writing a reviewable file locally,
        nothing touches the target) does NOT need this -- use
        `authorize_local_action` for that. This method is for the step
        after review, where something actually changes.
        """
        self.budget.check_runtime()
        self.approval.require("any_write_to_target", description)
        self.budget.note_tool_call()
        self.audit.record(
            "write_action_authorized", tool=tool_name, path=path, description=description
        )

    def record_result(self, tool_name: str, target: str, result_summary: str) -> None:
        self.audit.record(
            "tool_call_result", tool=tool_name, target=target, summary=result_summary
        )

    def record_refusal(self, tool_name: str, target: str, reason: str) -> None:
        self.audit.record("tool_call_refused", tool=tool_name, target=target, reason=reason)
