# Models — manifest contract

This directory holds **metadata only**. Weights (adapters, merged models,
GGUF) are never committed: a manifest is a few hundred bytes, a 1.7B Q4
GGUF is ~1 GB, and a checkout must not carry the latter.

```
models/
  <phase>/<version>/
    manifest.json      # committed (or written on the GPU box)
    adapter/           # NOT committed — LoRA weights
    merged/            # NOT committed — fp16 merge
    *.gguf             # NOT committed — runtime artefact
```

## manifest.json

```json
{
  "phase": "exploit",
  "version": "2026-10-25",
  "base_model": "Qwen/Qwen3-1.7B",
  "adapter": "models/exploit/2026-10-25/adapter",
  "sha256": "<64 hex chars of adapter_model.safetensors>",
  "trained_at": "2026-10-25T12:00:00Z",
  "eval": {"ndcg": 0.71},
  "baseline": {"ndcg": 0.64},
  "promoted": true
}
```

The loader (`phantom.automation.ai.registry`) refuses a manifest that is
missing, has no `eval`, has no `baseline` for a metric, scores below the
baseline, claims `promoted: true` while invalid, **or names an artefact that is
not on disk**. The last rule was added on 2026-11-02 after a promoted ranker's
`ranker.json` was deleted: the registry kept serving the manifest and
`trust_for("exploit")` still said `nudge`, so the runtime advertised an
authority it could not exercise. An unmeasured model is
never loaded "just to try it": that is how a regression ships.

## Phases

| phase | task | primary metric |
| --- | --- | --- |
| `exploit` | rank eligible access candidates | `ndcg` |
| `planner` | rank eligible capability moves (CPU linear ranker) | `ndcg` |
| `finding` | observation → typed finding | `exact_match` |
| `osint` | same-person signal proposal | `brier` |
| `social` | one plausible message | `rubric` |
| `scan_parse` | tool output → ports/services | `exact_match` |
| `evolution` | failure → triage label | `exact_match` |

## Operator workflow

1. `training/README.md` builds the dataset and trains the adapter on a GPU.
   The `planner` phase is the CPU exception: `training.planner_ranker` fits a
   pairwise linear model over `training/golden/planner.jsonl` and writes the
   weights next to its manifest (see `models/planner/planner-2026-11-08/`).
2. `training.eval` writes the eval JSON; the trainer embeds it in the
   manifest and refuses promotion below baseline.
3. `training.export` merges and prints the GGUF command.
4. Point Phantom at the GGUF (`PHANTOM_LLM_MODEL` / `ai.<phase>` config) and
   keep `--ai off` as the default: the deterministic engine must remain
   fully functional without any model.

## Security

- A manifest is data, not code: the runtime never executes a path from it.
- Adapters are only loaded from a local directory the operator configured.
- No model output is executed: every suggestion is validated against the
  phase schema and a closed id registry before it can influence a decision.
