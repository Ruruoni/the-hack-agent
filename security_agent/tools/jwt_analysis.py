"""JWT analysis — pure local parsing, no network call and no signature
verification (we don't have the target's key). Flags common weaknesses
so the model can decide what to probe next with `http_request`.
"""
from __future__ import annotations

import base64
import json
from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode())


class JwtAnalyzeTool(Tool):
    name = "jwt_analyze"
    description = (
        "Decode a JWT (header + payload, no signature verification) and "
        "flag common weaknesses: alg=none, weak/no expiry, sensitive data "
        "in the payload. Local parsing only — does not contact the target."
    )
    action_category = "passive_recon"
    parameters = {
        "type": "object",
        "properties": {"token": {"type": "string", "description": "The JWT string to analyze."}},
        "required": ["token"],
    }

    def run(self, guardrails: Guardrails, token: str, **_: Any) -> ToolResult:
        guardrails.authorize_local_action(self.name, "jwt-token", "local JWT structural analysis")

        parts = token.strip().split(".")
        if len(parts) < 2:
            return ToolResult(ok=False, summary="Not a JWT (expected 2-3 dot-separated parts).", data={})

        try:
            header = json.loads(_b64url_decode(parts[0]))
            payload = json.loads(_b64url_decode(parts[1]))
        except Exception as exc:  # noqa: BLE001
            return ToolResult(ok=False, summary=f"Failed to decode: {exc}", data={})

        findings = []
        alg = header.get("alg", "")
        if alg.lower() == "none":
            findings.append("CRITICAL: alg=none — server may accept an unsigned token.")
        if alg.upper().startswith("HS"):
            findings.append(
                f"alg={alg} (symmetric HMAC) — if the signing secret is weak/guessable/leaked, "
                "a forged token is possible. Do not brute-force the secret without approval."
            )
        if "exp" not in payload:
            findings.append("No 'exp' claim — token may never expire.")
        sensitive_keys = [k for k in payload if k.lower() in ("password", "ssn", "secret", "api_key")]
        if sensitive_keys:
            findings.append(f"Sensitive-looking claims in payload (base64 != encryption): {sensitive_keys}")

        summary = (
            f"header={json.dumps(header)}\npayload={json.dumps(payload)}\n\n"
            + ("\n".join(findings) if findings else "No obvious structural weaknesses found.")
        )
        guardrails.record_result(self.name, "jwt-token", summary[:500])
        return ToolResult(ok=True, summary=summary, data={"header": header, "payload": payload, "findings": findings})
