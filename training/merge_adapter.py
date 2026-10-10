"""Merge a trained LoRA adapter into the base model's weights.

Produces a single standalone model directory you can point
security_agent's AGENT_LLM_BASE_URL / Ollama / vLLM at directly, instead
of needing PEFT at inference time.

    python -m training.merge_adapter \
        --base-model Qwen/Qwen2.5-7B-Instruct \
        --adapter training/output/security-agent-lora \
        --output training/output/security-agent-merged

To then run it in Ollama, convert the merged directory to GGUF with
llama.cpp's convert_hf_to_gguf.py (not included here — see
https://github.com/ggml-org/llama.cpp), then `ollama create` a Modelfile
pointing at the resulting .gguf file.
"""
from __future__ import annotations

import argparse
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-model", required=True)
    parser.add_argument("--adapter", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    print(f"Loading base model {args.base_model} ...")
    base = AutoModelForCausalLM.from_pretrained(
        args.base_model, torch_dtype=torch.bfloat16, device_map="auto"
    )
    print(f"Loading adapter from {args.adapter} ...")
    merged = PeftModel.from_pretrained(base, str(args.adapter))
    merged = merged.merge_and_unload()

    args.output.mkdir(parents=True, exist_ok=True)
    merged.save_pretrained(str(args.output))
    AutoTokenizer.from_pretrained(args.base_model).save_pretrained(str(args.output))
    print(f"Merged model saved to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
