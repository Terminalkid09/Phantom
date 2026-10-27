# Training pipeline (one small model per phase)

Six bounded models, not one general one: `exploit`, `finding`, `osint`,
`social`, `scan_parse`, `evolution`. Each is a LoRA adapter on a small base
model (Qwen3-1.7B by default), trained on Phantom's own run artefacts and
evaluated on a hand-written golden set. The runtime loads only a manifest and
a GGUF; **nothing here is imported by Phantom**.

> No GPU/torch is required to build datasets, curate, evaluate predictions or
> dry-run the trainer. The real training path imports the GPU stack lazily.

## 1. Build the datasets

```bash
python -m training.build_dataset --phase all \
    --sessions-dir data/sessions \
    --experience data/experience_cases.json \
    --packs data/exploit_packs.json \
    --out training/data
```

Writes `training/data/<phase>.jsonl` plus `<phase>.manifest.json` (counts,
redactions, SHA-256). Secrets, e-mail addresses and Windows user paths are
redacted before writing; records without a real label are skipped, not
guessed.

## 2. Curate

```bash
python -m training.curate --in training/data --out training/data/curated \
    --workers 4
```

Drops empty/short answers, non-JSON labels, conversations over the length
cap, prompt-injection markers captured from target text, and duplicates.
`--workers` only parallelises the checks; output order is input order.

## 2b. Seed data for the thin phases

`osint`, `social` and `scan_parse` have almost no run artefacts in a normal
checkout (identity edges only exist if a run explored them, a draft only if a
campaign was built, and checkpoints store the command, not the scan output).
`training.synth` writes deterministic, clearly labelled seed examples for
exactly those three phases. Every label is validated against
`phantom.automation.ai.schemas`; a label the runtime would refuse is never
written.

```bash
python -m training.synth --out training/data/synth
# combine with the curated artefacts before training
for p in exploit finding osint social scan_parse evolution; do
  cat "training/data/curated/$p.jsonl" "training/data/synth/$p.jsonl" \
      2>/dev/null > "training/data/train/$p.jsonl"
done
```

Dataset labels are the **runtime** schema (`ranked`, `findings`, `links`,
`text`, `summary`), not a builder-private shape: a model trained on
`{"chosen": ...}` would be rejected by `validate_exploit` on every call.
`tests/test_training_schemas.py` pins the two sides together.

## 3. Train one phase (GPU)

```bash
python -m training.train_lora \
    --phase exploit \
    --base-model Qwen/Qwen3-1.7B \
    --dataset training/data/curated/exploit.jsonl \
    --output models/exploit/2026-10-25 \
    --version 2026-10-25 \
    --epochs 3 --lr 2e-4 --batch-size 1 --grad-accum 8 \
    --eval-json training/eval/exploit.json \
    --baseline-json training/eval/exploit.baseline.json
```

All phases, sequentially (one GPU, one adapter at a time):

```bash
for p in exploit finding osint social scan_parse evolution; do
  python -m training.train_lora --phase "$p" \
      --dataset "training/data/curated/$p.jsonl" \
      --output "models/$p/$(date +%F)" --version "$(date +%F)" \
      --eval-json "training/eval/$p.json" \
      --baseline-json "training/eval/$p.baseline.json" || break
done
```

The trainer writes `models/<phase>/<version>/manifest.json` and promotes the
adapter **only** when `eval` is present and every metric is at least the
baseline. Otherwise the runtime refuses to load it (see `models/README.md`).

`--dry-run` prints the resolved plan and exits without importing torch:

```bash
python -m training.train_lora --phase exploit --dataset x.jsonl \
    --output /tmp/out --dry-run
```

### Step 0: measure the machine before committing to a schedule

`--max-steps N` stops the run after N optimizer steps, logs every step and
prints a `measured` block (s/step, samples/s, runtime, loss). Run it once per
candidate base: the numbers decide the base and the epochs, and they are cheap
to take.

```bash
python -m training.train_lora --phase exploit \
    --base-model training/base/Qwen3-1.7B \
    --dataset training/data/train/exploit.jsonl \
    --output data/tmp/bench --version bench --epochs 1 \
    --no-4bit --batch-size 1 --grad-accum 1 --max-seq-len 512 \
    --completion-only --max-steps 3
```

Measured on the reference CPU box (Intel 16 threads, 33.8 GB RAM, torch
2.5.1+cpu, 113 exploit rows, mean 542 tokens/sample):

| base | s/step | samples/s | ~tokens/s |
| --- | --- | --- | --- |
| Qwen2.5-0.5B-Instruct | 2.372 | 0.422 | ~216 |
| Qwen3-1.7B | 7.355 | 0.136 | ~70 |

Loading a Qwen3 checkpoint needs `transformers >= 4.51` and, with it,
`accelerate >= 1.6`; older versions fail with `model type qwen3` (unrecognised
architecture) and then on `Accelerator.unwrap_model(keep_torch_compile=...)`.
`peft`/`trl` do not need to move for this: the completion-only collator is
still importable.

## 4. Evaluate

`training.eval` scores a predictions file, so the same numbers can be
produced on a laptop or in CI:

```bash
# predictions.jsonl: {"id": "exploit-1", "prediction": {"ranking": [...]}}
python -m training.eval --phase exploit \
    --predictions training/eval/exploit.pred.jsonl \
    --out training/eval/exploit.json \
    --baseline 0.64
```

Metrics (higher is better, which is how the manifest gate compares):

| metric | phase | meaning |
| --- | --- | --- |
| `ndcg` | exploit | discounted gain of the predicted ranking |
| `exact_match` | finding, scan_parse, evolution | normalised extraction equality |
| `brier` | osint | `1 - (expected - predicted)^2` |
| `pass_at_1` | code phases | first candidate passes the checker |
| `rubric` | social | supplied rubric callable returns 0..1 |

`rubric` needs a callable. `training.eval` now supplies the built-in one for
the `social` phase (`training/rubric.py`): the disqualifying tells are the ones
`phantom.automation.social.pretext_score` already refuses a campaign draft on,
and every golden criterion maps to one deterministic check over the draft plus
that row's `input` (interest, city, order number). Pass `--no-rubric` to score
0 instead, which is what the old behaviour was.

A rubric callable may take `(expected, prediction)` or
`(expected, prediction, context)`; `eval.rubric_takes_context` decides which,
so an existing two-argument rubric is untouched. A criterion with no check
scores 0: an unverifiable criterion is not a passed one.

### The golden set must speak the runtime schema

A fixture the runtime validator would refuse turns a CORRECT model into a
zero. `finding-2` expected `kind: "web_anomaly"`, a kind that exists nowhere in
`schemas.FINDING_KINDS`, while the schema-valid answer (`hunt_anomaly`) scored
exact_match 0.

```bash
python -m training.golden_check          # every phase, exit 1 on any error
python -m training.golden_check --phase finding
```

Each expectation is mapped into the payload its validator takes and checked
with that validator, and social rows are checked against the rubric's known
criteria. Run it after touching a golden file.

To obtain the baseline numbers, run the deterministic heuristic on the same
golden file and save its predictions, then score it with the same command.

### Run an adapter on the golden set

`training.predict` loads one adapter, generates a JSON answer for every
golden input, validates it against the runtime schema and converts it to the
shape the metric consumes (a refused answer becomes an empty prediction, so
it scores low instead of crashing):

```bash
# deterministic baseline (no model download)
python -m training.predict --phase exploit --baseline \
    --out training/eval/exploit.base.jsonl
python -m training.eval --phase exploit \
    --predictions training/eval/exploit.base.jsonl \
    --out training/eval/exploit.baseline.json

# the trained adapter
python -m training.predict --phase exploit \
    --adapter models/exploit/2026-10-26/adapter \
    --out training/eval/exploit.pred.jsonl
python -m training.eval --phase exploit \
    --predictions training/eval/exploit.pred.jsonl \
    --baseline 0.67 --out training/eval/exploit.json
```

`--base-model` defaults to `Qwen/Qwen2.5-0.5B-Instruct`, which also runs on
CPU for a smoke run (`--no-4bit`, `batch-size 1`): a 0.5B adapter on ~500
rows is minutes, not hours, and is the honest way to validate the wiring
before spending GPU time on Qwen3-1.7B.

## 5. Export to GGUF

```bash
python -m training.export \
    --base-model Qwen/Qwen3-1.7B \
    --adapter models/exploit/2026-10-25/adapter \
    --out models/exploit/2026-10-25/merged \
    --outtype q4_k_m
```

It merges the adapter and **prints** the exact `convert_hf_to_gguf.py` and
`llama-quantize` commands. The converter stays in your llama.cpp checkout;
no path is hardcoded and no download happens.

## Hardware and time (estimates, not promises)

| base | 4-bit VRAM | disk (cache + merged + GGUF) | 3 epochs on ~5k rows |
| --- | --- | --- | --- |
| Qwen3-0.6B | 4–6 GB | ~3 GB | 20–40 min (T4) |
| **Qwen3-1.7B** | **6–10 GB** | **~6 GB** | **1.5–4 h (T4)** |
| Qwen3-4B | 12–16 GB | ~12 GB | 4–8 h (A10/A100) |

Prefer 1.7B: it is the sweet spot for extraction/ranking, and six small
adapters stay cheaper than one 7B model that is mediocre at everything.
Fine-tuning teaches **behaviour** (JSON shape, ranking, phrasing). Facts
(CVEs, modules) are retrieved at runtime from NVD/ExploitDB, so a model does
not go stale when the vulnerability landscape changes.

## Colab / RunPod (no vendor lock)

```bash
pip install "torch>=2.3" transformers peft trl datasets \
    bitsandbytes accelerate
# clone the repo, put data/sessions or a small curated dataset on the box,
# then run the same commands above.
```

- Colab free/Pro: T4 16 GB fits 1.7B QLoRA; keep the dataset and adapters on
  Google Drive so a disconnect does not lose the epoch.
- RunPod/Lambda: an A10/A100 shortens 1.7B to under an hour; choose a plain
  PyTorch image, no proprietary trainer.
- After training: copy `models/<phase>/<version>/` (manifest + adapter) back;
  never commit weights.

## Parallelism

Parallelise **dataset curation, teacher-label generation and evaluation
shards** (they are independent per phase). Weight training is serial per
adapter: one GPU runs one job. Six phases can run in parallel only with six
GPUs; otherwise queue them.
