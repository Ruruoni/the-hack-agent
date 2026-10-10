"""Model-agnostic "brain" layer.

Every provider implements the same tiny interface — `chat(messages, tools)`
returning a normalized response — so the agent loop never knows or cares
whether it's talking to a free local model, a free-tier hosted API, or a
paid one. Swap providers with an env var, no code changes.

Supported out of the box:
  - ollama            : free, local, OpenAI-compatible (default)
  - groq              : free-tier hosted, OpenAI-compatible, fast
  - openai_compatible : any other OpenAI-compatible endpoint
                         (vLLM, LM Studio, OpenRouter, together.ai, etc.)
  - anthropic         : Claude, if you have an API key and want the
                         strongest planner for the hardest runs
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

from .config import ProviderConfig


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ChatResponse:
    content: str | None
    tool_calls: list[ToolCall]
    raw: dict[str, Any]
    usage_tokens: int = 0


class LLMProvider:
    def __init__(self, cfg: ProviderConfig):
        self.cfg = cfg

    def chat(self, messages: list[dict], tools: list[dict]) -> ChatResponse:
        raise NotImplementedError


class OpenAICompatibleProvider(LLMProvider):
    """Works for Ollama, Groq, vLLM, LM Studio, OpenRouter, together.ai —
    anything that speaks the `/v1/chat/completions` tool-calling schema.
    """

    def __init__(self, cfg: ProviderConfig):
        super().__init__(cfg)
        self.client = httpx.Client(timeout=120.0)

    def _endpoint(self) -> str:
        base = self.cfg.base_url.rstrip("/")
        # Ollama's native OpenAI-compatible route; others already expose /v1.
        if base.endswith("/v1"):
            return f"{base}/chat/completions"
        return f"{base}/v1/chat/completions"

    def chat(self, messages: list[dict], tools: list[dict]) -> ChatResponse:
        headers = {"Content-Type": "application/json"}
        if self.cfg.api_key:
            headers["Authorization"] = f"Bearer {self.cfg.api_key}"

        payload: dict[str, Any] = {
            "model": self.cfg.model,
            "messages": messages,
            "temperature": self.cfg.temperature,
            "max_tokens": self.cfg.max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        resp = self.client.post(self._endpoint(), headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()

        choice = data["choices"][0]["message"]
        raw_calls = choice.get("tool_calls") or []
        tool_calls = []
        for tc in raw_calls:
            fn = tc.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            tool_calls.append(ToolCall(id=tc.get("id", ""), name=fn.get("name", ""), arguments=args))

        usage = data.get("usage", {}).get("total_tokens", 0)
        return ChatResponse(
            content=choice.get("content"), tool_calls=tool_calls, raw=data, usage_tokens=usage
        )


class AnthropicProvider(LLMProvider):
    """Optional: use Claude as the brain for harder planning tasks. Requires
    AGENT_LLM_API_KEY. Not free, but included so you can mix a free model
    for routine triage with Claude for the planning step if you want.
    """

    def __init__(self, cfg: ProviderConfig):
        super().__init__(cfg)
        self.client = httpx.Client(timeout=120.0)

    def chat(self, messages: list[dict], tools: list[dict]) -> ChatResponse:
        system = "\n".join(m["content"] for m in messages if m["role"] == "system")
        convo = [m for m in messages if m["role"] != "system"]

        anthropic_tools = [
            {
                "name": t["function"]["name"],
                "description": t["function"].get("description", ""),
                "input_schema": t["function"].get("parameters", {}),
            }
            for t in tools
        ]

        payload = {
            "model": self.cfg.model,
            "system": system,
            "messages": convo,
            "max_tokens": self.cfg.max_tokens,
            "tools": anthropic_tools,
        }
        headers = {
            "x-api-key": self.cfg.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        resp = self.client.post(
            "https://api.anthropic.com/v1/messages", headers=headers, json=payload
        )
        resp.raise_for_status()
        data = resp.json()

        text_parts = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
        tool_calls = [
            ToolCall(id=b["id"], name=b["name"], arguments=b.get("input", {}))
            for b in data.get("content", [])
            if b.get("type") == "tool_use"
        ]
        usage = data.get("usage", {})
        total = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
        return ChatResponse(
            content="\n".join(text_parts) or None,
            tool_calls=tool_calls,
            raw=data,
            usage_tokens=total,
        )


def build_provider(cfg: ProviderConfig) -> LLMProvider:
    if cfg.kind in ("ollama", "groq", "openai_compatible"):
        return OpenAICompatibleProvider(cfg)
    if cfg.kind == "anthropic":
        return AnthropicProvider(cfg)
    raise ValueError(f"Unknown provider kind: {cfg.kind}")
