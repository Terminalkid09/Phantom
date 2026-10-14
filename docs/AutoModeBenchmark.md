# AutoMode benchmark — ground truth, failure injection, honest numbers

The audit's finding was blunt: the project had thousands of tests and **no
measurement**. "Gira senza LLM e ha resume/supervisor/checkpoint con budget —
**ma** `completed` ≠ goal raggiunto ... e **la misura manca**." A green suite
proved that nothing crashed; it said nothing about whether a run reached
anything, invented anything, or needed the operator every two moves.

`phantom/automation/benchmark.py` is that measurement, and
`scripts/automode_benchmark.py` is how you run it:

```bash
python scripts/automode_benchmark.py            # the standard suite
python scripts/automode_benchmark.py --list     # ground truth of each scenario
python scripts/automode_benchmark.py --json     # machine-readable report
python scripts/automode_benchmark.py --scenario fortress
```

CI runs it in the `offline-sims` job, and unlike the two coverage simulators
next to it **this step is gating**: a scenario that breaks its own declared
expectations fails the job.

## Three principles (why this is not a demo)

1. **Ground truth is declared, not observed.** A `Scenario` states what the
   target actually runs, which credentials it actually accepts and whether the
   goal is reachable at all. A finding outside that truth is a **false
   positive** — the agent inventing a service or a credential is scored, not
   celebrated.
2. **Failure injection is part of the scenario.** `failures={"nmap": 2}` makes
   the first two commands matching a token fail, so **recovery** is measured
   (moves between the injection and the next move that produced evidence)
   instead of assumed. An unrecovered failure reports `None`, never "0 moves,
   all good".
3. **The outcome is the production model's.** Success is whatever
   `phantom/automation/engagement_outcome.py` says it is — the same token the
   report and the UI show. The benchmark has no private idea of "done", and it
   flags a run whose outcome contradicts its own metrics as **dishonest**.

Everything is offline: a scripted runner answers every command and no packet
leaves the box.

## The metrics

| Metric | What it means | How it is measured |
|---|---|---|
| `goal_reached` / `outcome` | did the run reach the goal, and how does it end | the agent's `goal_reached` fact + `derive_target_outcome` |
| `partial` | work done, goal not reached | outcome token `partial` |
| `false_positives` | findings the target does not have | every finding scored against `services` / `creds` / `reachable` |
| `inappropriate_actions` | moves that must never be taken automatically | capabilities in the scenario's `forbidden` set that actually ran |
| `time_to_recover` | moves from the last injected failure to the next evidence | the Nth failure is the Nth injection; the first success after it |
| `budget` | OPSEC spend and the noise allowance, and whether either was crossed | the shared WorldModel's ledger (`opsec_spent`, `noise_score`) |
| `operator_interventions` | how often a human was needed | `handoff`/`confirm`/`consent`/`await_operator` events, plus `blocked` events that ask for one |
| `honest` | the outcome agrees with the metrics | a computed invariant, not a hand-set field |

Attempts are reconstructed from the **event stream the UI renders**, so the
metric and the operator see the same run.

## The standard scenarios

| Scenario | Target | Ground truth | What it proves |
|---|---|---|---|
| `open_target` | SSH + HTTP, one known credential | goal reachable | the full chain reaches a beacon, with **no** false positives and **no** forbidden move |
| `flaky_web_probe` | same box, the web fingerprint fails twice | goal still reachable via SSH | the run routes around a dead step **and the recovery is measured** |
| `scan_failure` | same box, the port scan fails twice | goal reachable in theory | **a known gap, measured**: the foothold path is not recovered and the run finishes `partial` instead of claiming success |
| `fortress` | SSH on 2222 only, admin UI on 8443, no credentials | goal **not** reachable | nothing checks in, so the run must not deploy a beacon and must not invent a service |
| `budget_capped` | the open box with a 1.0 OPSEC allowance | overrun expected | the overrun is **visible in the metrics**, not discovered after the fact |

`scan_failure` deserves the emphasis: it asserts *honesty*, not success. If a
future fix makes the agent recover there, the metric changes and the benchmark
still passes — which is the point. A benchmark that demanded failure would
punish an improvement.

## What the benchmark does NOT claim

* It does not execute on real targets: the failure injection is a scripted
  runner, so it measures the **decision and reporting path**, not tool
  behaviour. Cross-compilation and the per-OS artefact contract are covered by
  the `beacon-smoke` jobs and
  [`beacon_platform_matrix.md`](beacon_platform_matrix.md).
* It is not a performance benchmark: `time_to_recover` counts **moves**, not
  seconds, so it stays deterministic and clock-free (a wall-clock number on a
  shared runner would be noise, not signal).
* The suite is small on purpose. Adding a scenario is the intended way to
  extend it: declare the ground truth, declare the expectation, and let CI hold
  the line.
