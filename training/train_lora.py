"""train_lora.py — QLoRA fine-tune for ONE phase, on a GPU box.

This file is deliberately import-safe on a machine without torch: the heavy
stack (torch, transformers, peft, trl, datasets) is imported INSIDE the real
training path, after argument parsing. ``--dry-run`` prints the resolved
configuration and exits 0, which is how CI (and a laptop) validate the
pipeline without downloading a model.

Real run (single GPU, 12-24 GB VRAM is enough for a 1.7B QLoRA):

    python -m training.train_lora \
        --phase exploit \
        --base-model Qwen/Qwen3-1.7B \
        --dataset training/data/exploit.jsonl \
        --output models/exploit/2026-10-25 \
        --epochs 3 --lr 2e-4 --batch-size 1 --grad-accum 8 \
        --eval-json training/eval/exploit.json \
        --baseline-json training/golden/exploit.baseline.json

After training, the manifest is written next to the adapter. It is
``promoted`` only when the eval is present and not below the baseline; the
runtime refuses anything else.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from training.manifest import (
    build_manifest,
    sha256_file,
    validate_manifest,
    write_manifest,
)

DEFAULTS = {
    "base_model": "Qwen/Qwen3-1.7B",
    "epochs": 3.0,
    "lr": 2e-4,
    "batch_size": 1,
    "grad_accum": 8,
    "max_seq_len": 2048,
    "lora_r": 16,
    "lora_alpha": 32,
    "lora_dropout": 0.05,
    "seed": 42,
}


def resolve_config(args: argparse.Namespace) -> Dict[str, Any]:
    dataset = Path(args.dataset)
    rows = 0
    if dataset.is_file():
        with open(dataset, encoding="utf-8") as handle:
            rows = sum(1 for line in handle if line.strip())
    return {
        "phase": args.phase,
        "base_model": args.base_model,
        "dataset": str(dataset),
        "dataset_records": rows,
        "dataset_exists": dataset.is_file(),
        "output": str(Path(args.output)),
        "adapter_dir": str(Path(args.output) / "adapter"),
        "epochs": args.epochs,
        "lr": args.lr,
        "batch_size": args.batch_size,
        "grad_accum": args.grad_accum,
        "effective_batch": args.batch_size * args.grad_accum,
        "max_seq_len": args.max_seq_len,
        "lora_r": args.lora_r,
        "lora_alpha": args.lora_alpha,
        "lora_dropout": args.lora_dropout,
        "load_in_4bit": not args.no_4bit,
        "completion_only": bool(args.completion_only),
        "max_steps": int(getattr(args, "max_steps", 0) or 0),
        "seed": args.seed,
        "eval_json": args.eval_json,
        "baseline_json": args.baseline_json,
        "torch_required": True,
    }


def _load_rows(path: Path) -> List[dict]:
    rows: List[dict] = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            messages = record.get("messages")
            if isinstance(messages, list) and messages:
                rows.append({"messages": messages})
    return rows


def _read_scores(path: str) -> Dict[str, float]:
    if not path:
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if isinstance(data, dict) and isinstance(data.get("scores"), dict):
        data = data["scores"]
    if not isinstance(data, dict):
        return {}
    return {str(k): float(v) for k, v in data.items()
            if isinstance(v, (int, float)) and not isinstance(v, bool)}


def _format_text(tokenizer, messages: List[dict]) -> str:
    return tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=False)


def train(args: argparse.Namespace) -> int:
    """Real path: imports the GPU stack only here."""
    import torch
    from datasets import Dataset
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import (AutoModelForCausalLM, AutoTokenizer,
                              BitsAndBytesConfig)
    try:
        from trl import SFTConfig, SFTTrainer
    except ImportError:                       # older/newer trl layouts
        from transformers import TrainingArguments as SFTConfig
        from trl import SFTTrainer
    config = resolve_config(args)
    rows = _load_rows(Path(args.dataset))
    if not rows:
        print(f"no training rows in {args.dataset}", file=sys.stderr)
        return 2

    tokenizer = AutoTokenizer.from_pretrained(args.base_model,
                                              trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    collator = None
    if args.completion_only:
        # Loss on the ANSWER tokens only. Training on the prompt teaches the
        # model to reproduce the question; on a 0.5B smoke run that is the
        # difference between valid JSON and a plausible-looking fragment.
        from trl import DataCollatorForCompletionOnlyLM
        # Pass TOKEN IDS: with a string template the collator compares text
        # tokens and misses Qwen's special `<|im_start|>` token.
        marker = tokenizer.encode("<|im_start|>assistant\n",
                                  add_special_tokens=False)
        collator = DataCollatorForCompletionOnlyLM(
            response_template=marker, tokenizer=tokenizer)

    quant = None
    if not args.no_4bit:
        quant = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )
    model = AutoModelForCausalLM.from_pretrained(
        args.base_model, quantization_config=quant,
        device_map="auto", trust_remote_code=True)
    if quant is not None:
        model = prepare_model_for_kbit_training(model)
    lora = LoraConfig(
        r=args.lora_r, lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout, bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    )
    model = get_peft_model(model, lora)

    dataset = Dataset.from_list(
        [{"text": _format_text(tokenizer, row["messages"])}
         for row in rows])

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    max_steps = int(getattr(args, "max_steps", 0) or 0)
    common = {
        "output_dir": str(output_dir / "checkpoints"),
        "num_train_epochs": args.epochs,
        "learning_rate": args.lr,
        "per_device_train_batch_size": args.batch_size,
        "gradient_accumulation_steps": args.grad_accum,
        # a bounded measurement run logs every step: the point of it is the
        # per-step cost, and one line at the end hides which step stalled.
        "logging_steps": 1 if max_steps else 10,
        "save_strategy": "epoch",
        "bf16": torch.cuda.is_bf16_supported() if torch.cuda.is_available()
        else False,
        "seed": args.seed,
        "report_to": [],
    }
    if max_steps:
        # `-1` is HF's "no cap": the run stops after N optimizer steps so a
        # laptop/CPU box can MEASURE seconds-per-step and tokens-per-second
        # before a full schedule is committed to.
        common["max_steps"] = max_steps
    try:
        train_args = SFTConfig(
            **common, max_length=args.max_seq_len,
            dataset_text_field="text")
    except TypeError:
        # TRL renamed max_length -> max_seq_length across releases; accept
        # both, and fall back to plain TrainingArguments on old installs.
        try:
            train_args = SFTConfig(**common,
                                   max_seq_length=args.max_seq_len)
        except TypeError:
            train_args = SFTConfig(**common)

    trainer = SFTTrainer(model=model, args=train_args, train_dataset=dataset,
                         tokenizer=tokenizer, data_collator=collator)
    train_result = trainer.train()
    measured: Dict[str, Any] = {}
    if max_steps:
        metrics = dict(getattr(train_result, "metrics", {}) or {})
        runtime = float(metrics.get("train_runtime") or 0.0)
        per_step = float(metrics.get("train_steps_per_second") or 0.0)
        measured = {
            "max_steps": max_steps,
            "train_runtime_s": round(runtime, 2),
            "seconds_per_step": (round(runtime / max_steps, 3)
                                 if runtime else 0.0),
            "steps_per_second": round(per_step, 4),
            "samples_per_second": float(
                metrics.get("train_samples_per_second") or 0.0),
            "train_loss": metrics.get("train_loss"),
        }
        print(json.dumps({"measured": measured}, indent=2, sort_keys=True))

    adapter_dir = output_dir / "adapter"
    adapter_dir.mkdir(parents=True, exist_ok=True)
    trainer.model.save_pretrained(str(adapter_dir))
    tokenizer.save_pretrained(str(adapter_dir))

    eval_scores = _read_scores(args.eval_json)
    baseline = _read_scores(args.baseline_json)
    manifest = build_manifest(
        phase=args.phase, version=args.version,
        base_model=args.base_model, adapter=str(adapter_dir),
        sha256=sha256_file(adapter_dir / "adapter_model.safetensors"),
        eval_metrics=eval_scores, baseline=baseline,
    )
    errors = validate_manifest(manifest)
    write_manifest(manifest, output_dir)
    print(json.dumps({"config": config, "records": len(rows),
                      "manifest": manifest, "errors": errors,
                      "measured": measured},
                     indent=2, sort_keys=True))
    if errors:
        print("NOT promoted: " + "; ".join(errors), file=sys.stderr)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="training.train_lora",
        description="QLoRA fine-tune one Phantom phase (GPU required).")
    parser.add_argument("--phase", required=True, choices=[
        "exploit", "finding", "osint", "social", "scan_parse", "evolution"])
    parser.add_argument("--base-model", default=DEFAULTS["base_model"])
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--version", default="dev")
    parser.add_argument("--epochs", type=float, default=DEFAULTS["epochs"])
    parser.add_argument("--lr", type=float, default=DEFAULTS["lr"])
    parser.add_argument("--batch-size", type=int,
                        default=DEFAULTS["batch_size"])
    parser.add_argument("--grad-accum", type=int,
                        default=DEFAULTS["grad_accum"])
    parser.add_argument("--max-seq-len", type=int,
                        default=DEFAULTS["max_seq_len"])
    parser.add_argument("--lora-r", type=int, default=DEFAULTS["lora_r"])
    parser.add_argument("--lora-alpha", type=int,
                        default=DEFAULTS["lora_alpha"])
    parser.add_argument("--lora-dropout", type=float,
                        default=DEFAULTS["lora_dropout"])
    parser.add_argument("--seed", type=int, default=DEFAULTS["seed"])
    parser.add_argument("--no-4bit", action="store_true",
                        help="full-precision LoRA (needs much more VRAM)")
    parser.add_argument("--completion-only", action="store_true",
                        help="compute loss on the assistant answer only")
    parser.add_argument("--max-steps", type=int, default=0,
                        help="stop after N optimizer steps (bounded "
                             "measurement run: prints s/step and tokens/s); "
                             "0 = the full schedule")
    parser.add_argument("--eval-json", default="",
                        help='{"metric": score} produced by training.eval')
    parser.add_argument("--baseline-json", default="",
                        help='{"metric": score} the model must reach')
    parser.add_argument("--dry-run", action="store_true",
                        help="print the resolved plan; do NOT import torch")
    args = parser.parse_args(argv)

    if args.dry_run:
        print(json.dumps(resolve_config(args), indent=2, sort_keys=True))
        return 0
    return train(args)


if __name__ == "__main__":
    sys.exit(main())
