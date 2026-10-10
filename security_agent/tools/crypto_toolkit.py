"""Cryptography/encoding analysis -- a CyberChef-style local toolkit.

Pure in-process computation on text the model already has (no
subprocess, no network, no external binary) -- the same risk level as
jwt_analyze's local decode logic. Useful for decoding an obfuscated
payload found during an engagement (a secret hidden in Base64/hex, a
classic cipher in a CTF-style challenge, a hash to identify) without
needing a separate tool per encoding.
"""
from __future__ import annotations

import base64
import binascii
import codecs
from typing import Any

from ..guardrails import Guardrails
from .base import Tool, ToolResult

MORSE_CODE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
}
MORSE_DECODE = {v: k for k, v in MORSE_CODE.items()}

HASH_LENGTH_HINTS = {
    32: "MD5 or NTLM (32 hex chars)",
    40: "SHA-1 (40 hex chars)",
    56: "SHA-224 (56 hex chars)",
    64: "SHA-256 (64 hex chars)",
    96: "SHA-384 (96 hex chars)",
    128: "SHA-512 (128 hex chars)",
}


def _caesar(text: str, shift: int) -> str:
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


class CryptoToolkitTool(Tool):
    name = "crypto_toolkit"
    description = (
        "Encode/decode/analyze text using common schemes: base64, hex, "
        "binary, Caesar/ROT13, Morse code, XOR (with a given key), and "
        "hash-length identification. Pure local computation on text you "
        "already have -- no network, no target."
    )
    action_category = "passive_recon"
    parameters = {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "description": (
                    "One of: base64_encode, base64_decode, hex_encode, hex_decode, "
                    "binary_encode, binary_decode, caesar_encode, caesar_decode, rot13, "
                    "morse_encode, morse_decode, xor, identify_hash."
                ),
            },
            "text": {"type": "string", "description": "Input text/data."},
            "shift": {"type": "integer", "description": "For caesar_encode/caesar_decode.", "default": 13},
            "key": {"type": "string", "description": "For xor: the XOR key (as plain text)."},
        },
        "required": ["operation", "text"],
    }

    def run(
        self,
        guardrails: Guardrails,
        operation: str,
        text: str,
        shift: int = 13,
        key: str | None = None,
        **_: Any,
    ) -> ToolResult:
        guardrails.authorize_local_action(self.name, operation, f"crypto_toolkit {operation}")

        try:
            result = self._dispatch(operation, text, shift, key)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(ok=False, summary=f"error: {exc}", data={})

        guardrails.record_result(self.name, operation, result[:500])
        return ToolResult(ok=True, summary=result, data={"operation": operation})

    def _dispatch(self, operation: str, text: str, shift: int, key: str | None) -> str:
        if operation == "base64_encode":
            return base64.b64encode(text.encode()).decode()
        if operation == "base64_decode":
            return base64.b64decode(text).decode(errors="replace")
        if operation == "hex_encode":
            return text.encode().hex()
        if operation == "hex_decode":
            return binascii.unhexlify(text).decode(errors="replace")
        if operation == "binary_encode":
            return " ".join(format(b, "08b") for b in text.encode())
        if operation == "binary_decode":
            bytes_ = bytes(int(b, 2) for b in text.split())
            return bytes_.decode(errors="replace")
        if operation == "caesar_encode":
            return _caesar(text, shift)
        if operation == "caesar_decode":
            return _caesar(text, -shift)
        if operation == "rot13":
            return codecs.encode(text, "rot_13")
        if operation == "morse_encode":
            return " ".join(MORSE_CODE.get(ch.upper(), "") for ch in text if ch != " ")
        if operation == "morse_decode":
            return "".join(MORSE_DECODE.get(token, "?") for token in text.split())
        if operation == "xor":
            if not key:
                raise ValueError("xor requires a key")
            return _xor(text.encode(), key.encode()).hex()
        if operation == "identify_hash":
            candidate = text.strip()
            if not all(c in "0123456789abcdefABCDEF" for c in candidate):
                return "Not a hex string -- doesn't look like a common hash format."
            hint = HASH_LENGTH_HINTS.get(len(candidate))
            return hint or f"Unrecognized length ({len(candidate)} hex chars) for common hash algorithms."
        raise ValueError(f"Unknown operation '{operation}'")
