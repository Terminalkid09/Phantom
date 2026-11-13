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
``promoted`` only when the MEASUREMENT carries the claim, and it records the
basis it rests on (``promotion_basis`` / ``promotion_reason``, see
``training.manifest``); the runtime refuses anything else.

Measured defect closed here (2026-11-02): the trainer dropped the two facts
that make a promotion checkable. It read the eval report with a "every number
in this JSON is a metric" rule, so the report's own ``n`` and ``delta``
became "metrics" the baseline could never match, and it discarded the
``gate`` block ``training.eval --gate`` had just measured — leaving the
manifest to be judged on a bare mean, which is how a three-row tie came to be
written as ``"promoted": true``. ``golden_rows``, the sample size the eval
actually scored, now travels into the manifest from the report (or from
``--golden``), never from the size of the TRAINING set: those are different
numbers, and confusing them makes a three-row eval look like a measurement.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from training.manifest import (
    build_manifest,
    sha256_tree,
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
        "golden": args.golden,
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


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _read_report(path: str) -> Dict[str, Any]:
    """The whole eval/report JSON as a dict (``{}`` when unreadable)."""
    if not path:
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _read_scores(path: str) -> Dict[str, float]:
    """The metric -> score map a report (or a baseline file) carries.

    Read by SHAPE, because a ``training.eval`` report is not a score map: it
    names its metric (``metric``/``score``) or carries a ``scores`` map, and
    every other number in it (``n``, ``delta``, ``ci_low``) is context.
    Reading all of them — what this did until 2026-11-02 — invented metrics
    the baseline could never match, so a run that HAD measured something
    reported a comparison error instead of a result.
    """
    report = _read_report(path)
    if isinstance(report.get("scores"), dict):
        source: Dict[str, Any] = report["scores"]
    elif isinstance(report.get("metric"), str) \
            and _is_number(report.get("score")):
        return {str(report["metric"]): float(report["score"])}
    else:
        source = report
    return {str(key): float(value) for key, value in source.items()
            if _is_number(value)}


def _golden_rows(report: Dict[str, Any],
                 golden_path: str = "") -> Optional[int]:
    """The row count the eval was MEASURED on, ``None`` when it is unstated.

    ``training.eval`` states it (``n``, and again inside ``gate`` and
    ``baseline``); ``--golden`` states it by naming the file the eval scored.
    What is never used is the size of the training set: ``dataset_records``
    says how much the model READ, not how much the eval JUDGED, and a 3-row
    eval stays a 3-row eval however large the training set was.
    """
    for key in ("n", "rows"):
        value = report.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return int(value)
    for block in ("gate", "baseline"):
        nested = report.get(block)
        if isinstance(nested, dict):
            value = nested.get("n")
            if isinstance(value, int) and not isinstance(value, bool):
                return int(value)
    if golden_path and Path(golden_path).is_file():
        with open(golden_path, encoding="utf-8") as handle:
            return sum(1 for line in handle if line.strip())
    return None


def build_from_report(phase: str, version: str, base_model: str,
                      adapter: str, *, sha256: str = "",
                      eval_json: str = "", baseline_json: str = "",
                      golden_json: str = "",
                      dataset: str = "") -> Dict[str, object]:
    """The manifest for ONE measured run, built from what was measured.

    The gate that ``training.eval --gate`` wrote is FORWARDED instead of
    dropped, so a rejected verdict cannot be outvoted by a mean that happened
    to look larger, and ``golden_rows`` is forwarded so a three-row eval is
    refused as a promotion instead of quietly accepted as one. A report whose
    gate carries no verdict (an eval run without ``--gate``) is not forwarded:
    there is no statistical decision in it to honour.
    """
    report = _read_report(eval_json)
    extra: Dict[str, object] = {}
    if dataset:
        extra["dataset"] = str(dataset)
    rows = _golden_rows(report, golden_json)
    if rows is not None:
        extra["golden_rows"] = int(rows)
    gate = report.get("gate")
    if isinstance(gate, dict) and gate.get("verdict"):
        extra["eval_gate"] = dict(gate)
    return build_manifest(
        phase=phase, version=version, base_model=base_model, adapter=adapter,
        sha256=sha256, eval_metrics=_read_scores(eval_json),
        baseline=_read_scores(baseline_json), extra=extra)


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

    manifest = build_from_report(
        args.phase, args.version, args.base_model, str(adapter_dir),
        # The WHOLE adapter directory, not only the weights file: the runtime
        # verifies the tree digest, and a manifest that hashed one file while
        # the registry hashed the tree would refuse every promoted adapter.
        sha256=sha256_tree(adapter_dir),
        eval_json=args.eval_json, baseline_json=args.baseline_json,
        golden_json=args.golden, dataset=str(args.dataset),
    )
    errors = validate_manifest(manifest)
    write_manifest(manifest, output_dir)
    print(json.dumps({"config": config, "records": len(rows),
                      "manifest": manifest, "errors": errors,
                      "measured": measured},
                     indent=2, sort_keys=True))
    # The verdict is the manifest's, not the error list's: a run can be
    # honestly un-promoted (a tie, too few rows) with nothing invalid about
    # it, and announcing "NOT promoted: <errors>" in that case names a cause
    # that does not exist. The basis and the reason travel with it, so the
    # operator reads WHY without opening the file.
    state = "promoted" if manifest.get("promoted") else "NOT promoted"
    print(f"{state} ({manifest.get('promotion_basis')}): "
          f"{manifest.get('promotion_reason')}", file=sys.stderr)
    if errors:
        print("manifest problems: " + "; ".join(errors), file=sys.stderr)
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
    parser.add_argument("--golden", default="",
                        help="golden JSONL the eval scored: its row count is "
                             "recorded as golden_rows (the eval report's own "
                             "n wins when it states one). Never the size of "
                             "the training set.")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the resolved plan; do NOT import torch")
    args = parser.parse_args(argv)

    if args.dry_run:
        print(json.dumps(resolve_config(args), indent=2, sort_keys=True))
        return 0
    return train(args)


if __name__ == "__main__":
    sys.exit(main())
