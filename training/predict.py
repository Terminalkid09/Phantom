"""predict.py — run one trained adapter on a phase's golden set.

The evaluation harness consumes PREDICTIONS, and the runtime schemas return
different shapes than the golden files use (``ranked`` vs ``ranking``,
``findings`` vs ``open_ports``, ...). This module is the single place that
converts a validated runtime answer into the shape ``training.eval`` scores,
so a model is measured on what it would actually return to Phantom.

    python -m training.predict --phase exploit \
        --adapter models/exploit/2026-10-26/adapter \
        --out training/eval/exploit.pred.jsonl

    # deterministic baseline, no model load
    python -m training.predict --phase exploit --baseline \
        --out training/eval/exploit.base.jsonl

The model output is never trusted: a response that does not validate against
``phantom.automation.ai.schemas`` becomes an empty prediction (and therefore a
low score), never a crash and never a silent pass.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from phantom.automation.ai import schemas
from training.eval import GOLDEN_DIR, load_jsonl
from training.phases import PHASES

DEFAULT_BASE = "Qwen/Qwen2.5-0.5B-Instruct"
_JSON = re.compile(r"\{.*\}", re.DOTALL)
_OPEN_PORT = re.compile(r"(\d{1,5})/(?:tcp|udp)\s+open(?:\s+(\S+))?")


def _system(phase: str) -> str:
    return (f"You are Phantom's {phase} model. {PHASES[phase]['task']} "
            f"Answer with JSON matching the {PHASES[phase]['schema']} schema "
            f"only: no prose, no commands, no invented ids.")


def _json_from(text: str) -> Optional[dict]:
    match = _JSON.search(text or "")
    if not match:
        return None
    try:
        value = json.loads(match.group(0))
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def to_eval(phase: str, answer: dict, payload: dict) -> dict:
    """Runtime answer -> the shape ``training.eval`` compares."""
    if phase == "exploit":
        ranked = [row.get("id") for row in answer.get("ranked") or []
                  if isinstance(row, dict) and row.get("id")]
        return {"ranking": ranked}
    if phase == "finding":
        rows = [row for row in answer.get("findings") or []
                if isinstance(row, dict)]
        return {"value": rows[0]} if rows else {"value": {}}
    if phase == "scan_parse":
        ports = []
        for row in answer.get("findings") or []:
            if not isinstance(row, dict):
                continue
            port = row.get("port")
            if isinstance(port, str) and port.isdigit():
                port = int(port)
            if isinstance(port, int):
                ports.append(str(port))
        return {"open_ports": ports}
    if phase == "evolution":
        proposal = str(answer.get("proposal") or "")
        return {"value": {
            "cause": str(answer.get("summary") or ""),
            "repair": proposal,
            "new_capability": bool(proposal),
        }}
    if phase == "osint":
        candidate = payload.get("candidate") or {}
        handle = str(candidate.get("handle") or "").lower()
        platform = str(candidate.get("platform") or "").lower()
        best = 0.0
        for row in answer.get("links") or []:
            if not isinstance(row, dict):
                continue
            same = (str(row.get("handle") or "").lower() == handle
                    and str(row.get("platform") or "").lower() == platform)
            if same:
                best = max(best, float(row.get("confidence") or 0.0))
        return {"probability": best}
    if phase == "social":
        return {"value": str(answer.get("text") or "")}
    return {}


def _baseline(phase: str, payload: dict) -> dict:
    """The deterministic heuristic Phantom already uses, in eval shape."""
    if phase == "exploit":
        rows = list(payload.get("candidates") or [])
        rows.sort(key=lambda row: (
            bool(str(row.get("id", "")).upper().startswith("CVE-")),
            -float(row.get("cvss") or 0.0)))
        return {"ranking": [row.get("id") for row in rows]}
    if phase == "finding":
        obs = payload.get("observation") or {}
        keep = {k: obs.get(k) for k in
                ("kind", "key", "value", "confidence") if k in obs}
        return {"value": keep}
    if phase == "scan_parse":
        ports = [m.group(1) for m in _OPEN_PORT.finditer(
            str(payload.get("output") or ""))]
        return {"open_ports": sorted(set(ports), key=int)}
    if phase == "evolution":
        failure = payload.get("failure") or {}
        unblock = str(failure.get("unblock") or "")
        return {"value": {"cause": str(failure.get("reason") or ""),
                          "repair": unblock,
                          "new_capability": bool(unblock)}}
    if phase == "osint":
        primary = payload.get("primary") or {}
        candidate = payload.get("candidate") or {}
        same = (str(primary.get("handle") or "").lower()
                == str(candidate.get("handle") or "").lower())
        return {"probability": 0.6 if same else 0.2}
    return {"value": ""}


_LOADED: Dict[tuple, tuple] = {}


def _load(base_model: str, adapter: str):
    """Load the base + adapter once per process, not once per golden row."""
    key = (base_model, adapter)
    if key not in _LOADED:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(base_model,
                                                  trust_remote_code=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        model = AutoModelForCausalLM.from_pretrained(
            base_model, torch_dtype=torch.float32, trust_remote_code=True)
        if adapter:
            from peft import PeftModel
            model = PeftModel.from_pretrained(model, adapter)
        _LOADED[key] = (tokenizer, model.to("cpu").eval())
    return _LOADED[key]


def _generate(phase: str, payload: dict, *, base_model: str,
              adapter: str = "", max_new_tokens: int = 256) -> dict:
    import torch
    tokenizer, model = _load(base_model, adapter)
    messages = [
        {"role": "system", "content": _system(phase)},
        {"role": "user", "content": json.dumps(payload, sort_keys=True,
                                               ensure_ascii=False)},
    ]
    prompt = tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=max_new_tokens,
                             do_sample=False,
                             pad_token_id=tokenizer.pad_token_id)
    text = tokenizer.decode(out[0][inputs["input_ids"].shape[1]:],
                            skip_special_tokens=True)
    data = _json_from(text)
    if data is None or schemas.validate(phase, data):
        return {}
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="training.predict")
    parser.add_argument("--phase", required=True, choices=list(PHASES))
    parser.add_argument("--adapter", default="")
    parser.add_argument("--base-model", default=DEFAULT_BASE)
    parser.add_argument("--golden", default="")
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-new-tokens", type=int, default=256)
    parser.add_argument("--baseline", action="store_true",
                        help="use the deterministic heuristic, no model")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args(argv)

    golden_path = Path(args.golden) if args.golden else \
        GOLDEN_DIR / f"{args.phase}.jsonl"
    golden = load_jsonl(golden_path)
    if not golden:
        print(f"no golden records at {golden_path}", file=sys.stderr)
        return 2
    if args.limit:
        golden = golden[:args.limit]

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
        for record in golden:
            payload = record.get("input") or {}
            if args.baseline:
                prediction = _baseline(args.phase, payload)
            else:
                answer = _generate(args.phase, payload,
                                   base_model=args.base_model,
                                   adapter=args.adapter,
                                   max_new_tokens=args.max_new_tokens)
                prediction = to_eval(args.phase, answer, payload)
            handle.write(json.dumps({"id": record.get("id"),
                                     "prediction": prediction},
                                    sort_keys=True) + "\n")
    print(f"{args.phase}: wrote {len(golden)} prediction(s) -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
