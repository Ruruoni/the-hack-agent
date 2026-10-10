"""Credential testing and offline hash cracking.

Deliberately narrow versions of what Hydra/Medusa and Hashcat/John the
Ripper can do in general -- these wrappers hard-cap scope (small
wordlist, one target account, short time budget) rather than exposing
the underlying tool's full generality. Both sit in the `exploitation`
category and are in scope.yaml's `require_human_approval_for` by
default, so every single call blocks on an explicit human "yes" --
never assumed, never cached across calls.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult

MAX_WORDLIST_LINES = 25  # hard ceiling regardless of what's requested


class CredentialTestTool(Tool):
    name = "credential_test"
    description = (
        "Test a small, explicit list of credentials (at most 25) against "
        "ONE specific account/service using Hydra. For bounded, "
        "already-approved credential testing against a test account you "
        "control -- never a real user's account, never a broad spray. "
        "Always blocks on human approval (exploitation category)."
    )
    action_category = "exploitation"
    binary = "hydra"
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host/service to test against."},
            "service": {"type": "string", "description": "Hydra service module, e.g. 'ssh', 'http-post-form'."},
            "username": {"type": "string", "description": "The single account being tested."},
            "password_list": {
                "type": "array",
                "items": {"type": "string"},
                "description": "At most 25 candidate passwords -- keep this small and purposeful.",
            },
        },
        "required": ["target", "service", "username", "password_list"],
    }

    def run(
        self,
        guardrails: Guardrails,
        target: str,
        service: str,
        username: str,
        password_list: list[str],
        **_: Any,
    ) -> ToolResult:
        if len(password_list) > MAX_WORDLIST_LINES:
            password_list = password_list[:MAX_WORDLIST_LINES]

        guardrails.authorize_tool_call(
            self.name, target, self.action_category,
            f"Hydra credential test: {len(password_list)} candidate password(s) "
            f"for account '{username}' against {service}://{target}",
        )
        if not self.available():
            msg = "hydra is not installed on this runner."
            guardrails.record_refusal(self.name, target, msg)
            return ToolResult(ok=False, summary=msg, data={})

        import tempfile

        wordlist_path = Path(tempfile.mkstemp(suffix=".txt")[1])
        wordlist_path.write_text("\n".join(password_list), encoding="utf-8")

        cmd = ["hydra", "-l", username, "-P", str(wordlist_path), "-t", "1", target, service]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=300)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, target, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})
        finally:
            wordlist_path.unlink(missing_ok=True)

        guardrails.record_result(self.name, target, (out or err)[:500])
        return ToolResult(ok=rc == 0, summary=out or err, data={"returncode": rc})


class HashCrackTool(Tool):
    name = "hash_crack"
    description = (
        "Attempt to crack password hashes using Hashcat, against a local "
        "hash file already obtained through a separately-approved "
        "extraction step (e.g. a sql_injection_test dump) -- this tool "
        "does not extract anything itself, only cracks what's already in "
        "the given file. Time-boxed. Always blocks on human approval."
    )
    action_category = "exploitation"
    binary = "hashcat"
    parameters = {
        "type": "object",
        "properties": {
            "hash_file": {"type": "string", "description": "Local path to the hash file to crack."},
            "hash_mode": {"type": "string", "description": "Hashcat -m mode number, e.g. '0' for MD5, '1000' for NTLM."},
            "wordlist": {"type": "string", "description": "Local path to a wordlist file."},
            "max_runtime_seconds": {"type": "integer", "default": 120},
        },
        "required": ["hash_file", "hash_mode", "wordlist"],
    }

    def run(
        self,
        guardrails: Guardrails,
        hash_file: str,
        hash_mode: str,
        wordlist: str,
        max_runtime_seconds: int = 120,
        **_: Any,
    ) -> ToolResult:
        guardrails.authorize_local_exploitation_action(
            self.name, hash_file,
            f"Hashcat crack attempt on {hash_file} (mode {hash_mode}), capped at {max_runtime_seconds}s",
        )

        if not self.available():
            msg = "hashcat is not installed on this runner."
            guardrails.record_refusal(self.name, hash_file, msg)
            return ToolResult(ok=False, summary=msg, data={})

        max_runtime_seconds = max(10, min(max_runtime_seconds, 600))
        cmd = [
            "timeout", str(max_runtime_seconds),
            "hashcat", "-m", hash_mode, "-a", "0", hash_file, wordlist,
        ]
        try:
            rc, out, err = self._run_subprocess(cmd, timeout=max_runtime_seconds + 30)
        except Exception as exc:  # noqa: BLE001
            guardrails.record_result(self.name, hash_file, f"error: {exc}")
            return ToolResult(ok=False, summary=str(exc), data={})

        guardrails.record_result(self.name, hash_file, (out or err)[-500:])
        return ToolResult(ok=True, summary=out or err, data={"returncode": rc})
