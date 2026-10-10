"""Bug report formatting and (gated) submission.

Mirrors remediation.py's split exactly:
- `format_bug_report` only ever writes a reviewable file locally --
  never approval-gated, same as propose_fix and the run report itself.
- `submit_bug_report` actually sends something to a third party
  outside this session (email, or a bug-bounty platform's API) --
  irreversible the moment it sends, so it always forces human approval
  under `external_disclosure`, unconditionally, and validates the
  recipient's domain against scope.yaml before anything else, the same
  way phishing_simulation_launch validates its recipients.
"""
from __future__ import annotations

import os
import re
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import httpx

from .. import config as cfg
from ..guardrails import Guardrails, ScopeViolation
from .base import Tool, ToolResult


def _slugify(text: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower())
    return text.strip("-")[:60] or "report"


HACKERONE_TEMPLATE = """\
# {title}

**Severity:** {severity}
**Weakness (CWE):** {weakness}

## Summary

{summary}

## Steps to Reproduce

{steps_to_reproduce}

## Impact

{impact}

## Supporting Material / Evidence

{evidence}

## Suggested Fix

{suggested_fix}
"""


class FormatBugReportTool(Tool):
    name = "format_bug_report"
    description = (
        "Format a confirmed finding (and its propose_fix draft, if any) "
        "into a standard bug-bounty report template (HackerOne-style: "
        "Summary, Steps to Reproduce, Impact, Evidence, Suggested Fix) "
        "and write it to a downloadable file. Drafting only -- never "
        "touches anything, never sent anywhere, no approval needed."
    )
    action_category = "passive_recon"  # drafting only
    parameters = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "severity": {"type": "string", "description": "Critical/High/Medium/Low/Info."},
            "weakness": {"type": "string", "description": "CWE ID/name if known, e.g. 'CWE-89 SQL Injection'."},
            "summary": {"type": "string"},
            "steps_to_reproduce": {"type": "string"},
            "impact": {"type": "string"},
            "evidence": {"type": "string", "description": "Logs, request/response excerpts, screenshots paths, etc."},
            "suggested_fix": {
                "type": "string",
                "description": "Summary of the fix -- reference the propose_fix draft file if one exists.",
            },
        },
        "required": ["title", "severity", "summary", "steps_to_reproduce", "impact", "suggested_fix"],
    }

    def run(
        self,
        guardrails: Guardrails,
        title: str,
        severity: str,
        summary: str,
        steps_to_reproduce: str,
        impact: str,
        suggested_fix: str,
        weakness: str = "",
        evidence: str = "",
        **_: Any,
    ) -> ToolResult:
        guardrails.authorize_local_action(self.name, title, f"Format bug report: {title}")

        reports_dir = cfg.REPORTS_DIR / "bug_reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        path = reports_dir / f"{ts}-{_slugify(title)}.md"

        content = HACKERONE_TEMPLATE.format(
            title=title, severity=severity, weakness=weakness or "N/A",
            summary=summary, steps_to_reproduce=steps_to_reproduce,
            impact=impact, evidence=evidence or "N/A", suggested_fix=suggested_fix,
        )
        path.write_text(content, encoding="utf-8")

        guardrails.record_result(self.name, title, f"Bug report written to {path}")
        return ToolResult(ok=True, summary=f"Bug report written to {path}", data={"path": str(path)})


class SubmitBugReportTool(Tool):
    name = "submit_bug_report"
    description = (
        "Send an already-formatted bug report (see format_bug_report) to "
        "the organization's own disclosure channel -- email, or a "
        "bug-bounty platform's API. The recipient must be in "
        "scope.yaml's disclosure.allowed_recipients (separate from the "
        "tested target's own domain -- the real security contact is "
        "often different). Always requires explicit human approval, "
        "unconditionally -- this leaves the session and cannot be "
        "undone once sent."
    )
    action_category = "external_disclosure"
    parameters = {
        "type": "object",
        "properties": {
            "report_file": {"type": "string", "description": "Path to a format_bug_report output file."},
            "method": {"type": "string", "description": "'email' or 'api'.", "default": "email"},
            "recipient_email": {
                "type": "string",
                "description": "For method='email': the organization's security contact. Must be listed in scope.yaml's disclosure.allowed_recipients.",
            },
            "smtp_host": {"type": "string", "description": "For method='email'."},
            "from_email": {"type": "string", "description": "For method='email'."},
            "api_url": {
                "type": "string",
                "description": "For method='api': the platform's report-submission endpoint. Its host must be listed in scope.yaml's disclosure.allowed_recipients.",
            },
            "api_key": {"type": "string", "description": "For method='api'."},
        },
        "required": ["report_file", "method"],
    }

    def available(self) -> bool:
        return True  # no external binary; uses smtplib/httpx directly

    def run(
        self,
        guardrails: Guardrails,
        report_file: str,
        method: str = "email",
        recipient_email: str | None = None,
        smtp_host: str | None = None,
        from_email: str | None = None,
        api_url: str | None = None,
        api_key: str | None = None,
        **_: Any,
    ) -> ToolResult:
        report_path = Path(report_file)
        if not report_path.is_file():
            return ToolResult(ok=False, summary=f"{report_file} does not exist.", data={})
        report_text = report_path.read_text(encoding="utf-8")

        if method == "email":
            if not recipient_email:
                return ToolResult(ok=False, summary="recipient_email is required for method='email'.", data={})
            try:
                guardrails.scope.check_disclosure_recipient(recipient_email)
            except ScopeViolation as exc:
                guardrails.record_refusal(self.name, recipient_email, str(exc))
                raise

            guardrails.authorize_external_disclosure_action(
                self.name, recipient_email, f"Email bug report {report_path.name} to {recipient_email}"
            )
            return self._send_email(guardrails, report_text, report_path, recipient_email, smtp_host, from_email)

        if method == "api":
            if not api_url:
                return ToolResult(ok=False, summary="api_url is required for method='api'.", data={})
            host = api_url.split("//")[-1].split("/")[0]
            try:
                guardrails.scope.check_disclosure_recipient(host)
            except ScopeViolation as exc:
                guardrails.record_refusal(self.name, api_url, str(exc))
                raise

            guardrails.authorize_external_disclosure_action(
                self.name, api_url, f"Submit bug report {report_path.name} via API to {api_url}"
            )
            return self._send_api(guardrails, report_text, report_path, api_url, api_key)

        return ToolResult(ok=False, summary=f"Unknown method '{method}' -- use 'email' or 'api'.", data={})

    def _send_email(self, guardrails, report_text, report_path, recipient_email, smtp_host, from_email):
        smtp_host = smtp_host or os.environ.get("BUG_REPORT_SMTP_HOST")
        from_email = from_email or os.environ.get("BUG_REPORT_FROM_EMAIL")
        if not smtp_host or not from_email:
            msg = "smtp_host/from_email not provided and BUG_REPORT_SMTP_HOST/BUG_REPORT_FROM_EMAIL not set."
            guardrails.record_refusal(self.name, recipient_email, msg)
            return ToolResult(ok=False, summary=msg, data={})

        msg = EmailMessage()
        msg["Subject"] = f"Security vulnerability report: {report_path.stem}"
        msg["From"] = from_email
        msg["To"] = recipient_email
        msg.set_content(report_text)

        try:
            with smtplib.SMTP(smtp_host, timeout=30) as server:
                server.starttls()
                password = os.environ.get("BUG_REPORT_SMTP_PASSWORD")
                if password:
                    server.login(from_email, password)
                server.send_message(msg)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, recipient_email, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        summary = f"Bug report emailed to {recipient_email}."
        guardrails.record_result(self.name, recipient_email, summary)
        return ToolResult(ok=True, summary=summary, data={"recipient": recipient_email})

    def _send_api(self, guardrails, report_text, report_path, api_url, api_key):
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        try:
            with httpx.Client(timeout=30.0) as client:
                resp = client.post(api_url, headers=headers, json={"report": report_text})
                resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, api_url, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        summary = f"Bug report submitted via API: {resp.status_code} {resp.text[:300]}"
        guardrails.record_result(self.name, api_url, summary)
        return ToolResult(ok=True, summary=summary, data={"status_code": resp.status_code})
