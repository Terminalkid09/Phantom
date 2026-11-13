"""export.py — merged model + GGUF command for llama.cpp.

The runtime loads GGUF through llama.cpp, so a promoted adapter has to be
merged into its base and converted. This script does the merge and PRINTS
the exact conversion command: it does not silently download or run a
converter, because the converter lives in the operator's llama.cpp checkout
and its path is machine-specific.

    python -m training.export \
        --base-model Qwen/Qwen3-1.7B \
        --adapter models/exploit/2026-10-25/adapter \
        --out models/exploit/2026-10-25/merged \
        --outtype q4_k_m

    # then, in the llama.cpp checkout:
    python convert_hf_to_gguf.py <merged> --outfile <merged>.gguf \
        --outtype q4_k_m

``--dry-run`` prints the resolved plan without importing torch.
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path
from typing import Any, Dict, Optional


def resolve(args: argparse.Namespace) -> Dict[str, Any]:
    out = Path(args.out)
    return {
        "base_model": args.base_model,
        "adapter": str(Path(args.adapter)),
        "adapter_exists": Path(args.adapter).is_dir(),
        "merged_dir": str(out),
        "outtype": args.outtype,
        "convert_command": (
            "python convert_hf_to_gguf.py "
            f"{shlex.quote(str(out))} "
            f"--outfile {shlex.quote(str(out) + '.gguf')} "
            f"--outtype {args.outtype}"),
        "quantize_command": (
            f"./llama-quantize {shlex.quote(str(out) + '.gguf')} "
            f"{shlex.quote(str(out) + '-' + args.outtype + '.gguf')} "
            f"{args.outtype.upper()}"),
        "torch_required": True,
    }


def export(args: argparse.Namespace) -> int:
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    plan = resolve(args)
    if not plan["adapter_exists"]:
        print(f"adapter directory not found: {args.adapter}", file=sys.stderr)
        return 2
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    tokenizer = AutoTokenizer.from_pretrained(args.base_model,
                                              trust_remote_code=True)
    base = AutoModelForCausalLM.from_pretrained(
        args.base_model, torch_dtype=torch.float16, device_map="cpu",
        trust_remote_code=True)
    model = PeftModel.from_pretrained(base, args.adapter)
    model = model.merge_and_unload()
    model.save_pretrained(str(out), safe_serialization=True)
    tokenizer.save_pretrained(str(out))

    print(json.dumps(plan, indent=2, sort_keys=True))
    print("\nNext, in your llama.cpp checkout:\n  "
          + plan["convert_command"])
    if args.outtype != "f16":
        print("  " + plan["quantize_command"])
    return 0


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="training.export",
        description="Merge a LoRA adapter and print the GGUF command.")
    parser.add_argument("--base-model", required=True)
    parser.add_argument("--adapter", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--outtype", default="q4_k_m",
                        choices=["f16", "q8_0", "q5_k_m", "q4_k_m", "q4_0"])
    parser.add_argument("--dry-run", action="store_true",
                        help="print the plan; do NOT import torch")
    args = parser.parse_args(argv)
    if args.dry_run:
        print(json.dumps(resolve(args), indent=2, sort_keys=True))
        return 0
    return export(args)


if __name__ == "__main__":
    sys.exit(main())
