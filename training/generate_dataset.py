"""Synthesize an instruction-tuning dataset from knowledge/playbooks/.

Digestion, not injection: this is step 1 of actually baking the OWASP/
AI-agent/governance methodology into a model's weights, rather than
pasting it into the prompt every run. It turns each playbook into many
realistic (scenario -> ideal response) training examples, written out as
chat-format JSONL ready for `finetune_lora.py`.

Reuses security_agent's own model-agnostic provider layer to do the
generation — point it at any configured LLM (a strong hosted model is a
good choice for *generating* the data even if you fine-tune a small
local model as the *target*).

    python -m training.generate_dataset --examples-per-playbook 20

Output: training/dataset/train.jsonl (one {"messages": [...]} per line).
Review this file before training — it's the actual training signal.
"""
from __future__ import annotations

import argparse
import json
import logging
import random
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from security_agent.config import load_config  # noqa: E402
from security_agent.providers import build_provider  # noqa: E402
from security_agent.memory import KnowledgeBase  # noqa: E402

logger = logging.getLogger("generate_dataset")

AGENT_SYSTEM_PROMPT = (
    "You are an authorized security testing assistant operating strictly "
    "inside the boundaries of scope.yaml. Follow the OWASP/AI-agent/"
    "governance methodology you were trained on: confirm scope, prefer the "
    "minimal action that confirms a finding, never propose exploitation or "
    "destructive actions as something that just happens, and report "
    "findings with severity, breach pattern, ATT&CK mapping, and "
    "NIST/ISO/CIS/PCI framework references."
)

GENERATION_PROMPT_TEMPLATE = """You are building a fine-tuning dataset for a security-testing AI agent. \
Below is one playbook from that agent's methodology. Generate {n} diverse, \
realistic TRAINING EXAMPLES that teach a model to apply this playbook \
correctly.

Each example must be a JSON object with exactly two fields:
- "scenario": a short, realistic task a user or orchestrator might give the \
agent (a specific target type/situation relevant to this playbook — vary \
the industry, tech stack, and specific sub-case covered in the playbook).
- "ideal_response": the response a well-trained agent should give: which \
phase/step applies, which tool(s) it would call and with what reasoning, \
what a finding would look like (title, evidence, severity, remediation, \
and - when the playbook is a01-a11 - how it maps to breach pattern/ATT&CK/ \
NIST/ISO/CIS/PCI per the b01 reporting template), and explicitly noting \
where human approval would be required. Do not actually include real \
exploit payloads against real infrastructure — keep examples educational \
and generic (use placeholder hosts like "app.example-lab.local").

Output ONLY a JSON array of {n} such objects, nothing else — no markdown \
fences, no commentary.

PLAYBOOK ({filename}):
---
{content}
---
"""


def _extract_json_array(text: str) -> list[dict]:
    text = text.strip()
    # Strip markdown code fences if the model added them anyway.
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end < start:
        raise ValueError("No JSON array found in model output.")
    return json.loads(text[start : end + 1])


def generate_for_playbook(provider, filename: str, content: str, n: int) -> list[dict]:
    prompt = GENERATION_PROMPT_TEMPLATE.format(n=n, filename=filename, content=content)
    messages = [
        {"role": "system", "content": "You generate high-quality fine-tuning data. Output valid JSON only."},
        {"role": "user", "content": prompt},
    ]
    response = provider.chat(messages, tools=[])
    try:
        items = _extract_json_array(response.content or "")
    except (ValueError, json.JSONDecodeError) as exc:
        logger.warning("Failed to parse generation output for %s: %s", filename, exc)
        return []

    examples = []
    for item in items:
        scenario = item.get("scenario")
        ideal = item.get("ideal_response")
        if scenario and ideal:
            examples.append({"scenario": scenario.strip(), "ideal_response": ideal.strip()})
    return examples


def to_chat_record(scenario: str, ideal_response: str) -> dict:
    return {
        "messages": [
            {"role": "system", "content": AGENT_SYSTEM_PROMPT},
            {"role": "user", "content": scenario},
            {"role": "assistant", "content": ideal_response},
        ]
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--examples-per-playbook", type=int, default=20,
        help="Number of training examples to synthesize per playbook file.",
    )
    parser.add_argument(
        "--output", type=Path, default=REPO_ROOT / "training" / "dataset" / "train.jsonl",
    )
    parser.add_argument(
        "--val-split", type=float, default=0.1,
        help="Fraction of examples held out into train.val.jsonl for eval during training.",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")

    config = load_config()
    provider = build_provider(config.provider)
    kb = KnowledgeBase()
    files = sorted(kb.playbooks_dir.glob("*.md"))
    if not files:
        logger.error("No playbooks found in knowledge/playbooks/.")
        return 1

    all_records: list[dict] = []
    for f in files:
        logger.info("Generating %d examples from %s ...", args.examples_per_playbook, f.name)
        content = f.read_text(encoding="utf-8")
        examples = generate_for_playbook(provider, f.name, content, args.examples_per_playbook)
        logger.info("  -> got %d usable examples", len(examples))
        for ex in examples:
            all_records.append(to_chat_record(ex["scenario"], ex["ideal_response"]))

    if not all_records:
        logger.error("No examples were generated at all — check your AGENT_LLM_* provider settings.")
        return 1

    random.Random(args.seed).shuffle(all_records)
    split_idx = max(1, int(len(all_records) * (1 - args.val_split)))
    train_records, val_records = all_records[:split_idx], all_records[split_idx:]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        for rec in train_records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    val_path = args.output.with_name(args.output.stem + ".val.jsonl")
    with open(val_path, "w", encoding="utf-8") as f:
        for rec in val_records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    logger.info(
        "Wrote %d training examples to %s and %d validation examples to %s.",
        len(train_records), args.output, len(val_records), val_path,
    )
    logger.info("Review these before training — this is the actual training signal.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
