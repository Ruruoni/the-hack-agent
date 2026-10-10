"""QLoRA fine-tune an open-weight model on the generated dataset.

This is step 2: actually digesting training/dataset/train.jsonl into a
model's weights (a LoRA adapter), rather than pasting the playbooks into
every prompt. Requires a GPU with enough VRAM for the base model at
4-bit (a 7B-8B model needs roughly 6-8GB VRAM at 4-bit plus adapter/
optimizer overhead — 12GB+ is a comfortable minimum).

    pip install -r training/requirements.txt
    python -m training.finetune_lora \
        --base-model Qwen/Qwen2.5-7B-Instruct \
        --dataset training/dataset/train.jsonl \
        --val-dataset training/dataset/train.val.jsonl \
        --output training/output/security-agent-lora

After training, see training/README.md for how to use the adapter
(merge it, or load it directly with PEFT/vLLM, or convert to GGUF for
Ollama).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_jsonl_dataset(path: Path):
    from datasets import Dataset

    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return Dataset.from_list(records)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-model", default="Qwen/Qwen2.5-7B-Instruct",
        help="Hugging Face model id of the open-weight base model to fine-tune.",
    )
    parser.add_argument("--dataset", type=Path, default=REPO_ROOT / "training/dataset/train.jsonl")
    parser.add_argument("--val-dataset", type=Path, default=REPO_ROOT / "training/dataset/train.val.jsonl")
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "training/output/security-agent-lora")
    parser.add_argument("--epochs", type=float, default=3.0)
    parser.add_argument("--learning-rate", type=float, default=2e-4)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--grad-accum-steps", type=int, default=8)
    parser.add_argument("--max-seq-length", type=int, default=2048)
    parser.add_argument("--lora-r", type=int, default=16)
    parser.add_argument("--lora-alpha", type=int, default=32)
    parser.add_argument("--no-4bit", action="store_true", help="Disable 4-bit quantization (needs more VRAM).")
    args = parser.parse_args(argv)

    if not args.dataset.exists():
        parser.error(f"Dataset not found: {args.dataset}. Run training/generate_dataset.py first.")

    import torch
    from peft import LoraConfig, get_peft_model
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from trl import SFTConfig, SFTTrainer

    print(f"Loading base model {args.base_model} ...")
    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    quant_config = None
    if not args.no_4bit:
        quant_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )

    model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        quantization_config=quant_config,
        device_map="auto",
        torch_dtype=torch.bfloat16,
    )

    lora_config = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules="all-linear",
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    train_ds = load_jsonl_dataset(args.dataset)
    val_ds = load_jsonl_dataset(args.val_dataset) if args.val_dataset.exists() else None

    def format_chat(example):
        return {"text": tokenizer.apply_chat_template(example["messages"], tokenize=False)}

    train_ds = train_ds.map(format_chat)
    if val_ds is not None and len(val_ds) > 0:
        val_ds = val_ds.map(format_chat)
    else:
        val_ds = None

    sft_config = SFTConfig(
        output_dir=str(args.output),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum_steps,
        learning_rate=args.learning_rate,
        max_seq_length=args.max_seq_length,
        logging_steps=5,
        save_strategy="epoch",
        eval_strategy="epoch" if val_ds is not None else "no",
        bf16=True,
        report_to=[],
        dataset_text_field="text",
    )

    trainer = SFTTrainer(
        model=model,
        args=sft_config,
        train_dataset=train_ds,
        eval_dataset=val_ds,
    )

    print("Starting training ...")
    trainer.train()

    trainer.save_model(str(args.output))
    tokenizer.save_pretrained(str(args.output))
    print(f"\nDone. LoRA adapter saved to {args.output}")
    print("See training/README.md for how to use it (merge, PEFT inference, or GGUF export for Ollama).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
