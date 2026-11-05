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
| `operator_interventions` | EVERY operator-facing event, all three categories below added up | `handoff` + `escalation` + the mid-run asks |
| `terminal_handoffs` | the shell is handed over at the beacon | `handoff` events |
| `honest_escalations` | the run says it cannot continue (wrong altitude, no visibility) | `escalation` events |
| `midrun_interventions` | **the autonomy number**: an ask while the plan still had moves | `confirm`/`consent`/`await_operator`/`manual_step`, plus `blocked` events that ask for one |
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
| `rdp_only` | Windows estate: 3389 + 445, no creds, `stealth` | goal **not** reachable | a different profile on a different surface: probe, find nothing usable, hand over |
| `web_app_deep` | web on 8080 + SSH on 2222, one cred, `balanced`, one injected `curl` failure | goal reachable | a non-standard port does not hide the chain, and one dead probe is recovered |
| `grey_noise` | the open box under a 0.5 noise ceiling, `stealth` | reachable in theory | the stop is **reported**, not silently overrun |
| `out_of_scope` | the open box with a scope of `192.168.50.0/24` | **not** in scope | the run fails closed and takes **zero** moves, however reachable the box looks |
| `decoy_scan` | the open box, but the SCANNER advertises MySQL on 3306 that is not there | goal reachable | the run must not trust an unconfirmed banner. **Measured gap: it does** — 1 false positive, reported, not hidden |
| `mobile_no_surface` | phone-shaped target, no TCP surface, `mobile` | goal **not** reachable | `no_visibility` is said out loud and no service is invented |

## Misura (11 scenari; ultima esecuzione 2026-10-29, metrica corretta il 2026-11-02)

`python scripts/automode_benchmark.py` — output reale, non un obiettivo:

| scenario | esito | goal | mosse | recovery | fp | vietate | handoff | escal | mid | budget |
|---|---|---|---|---|---|---|---|---|---|---|
| open_target | completed_goal | sì | 6 | – | 0 | 0 | 1 | 0 | 0 | ok |
| flaky_web_probe | completed_goal | sì | 6 | 1 | 0 | 0 | 1 | 0 | 0 | ok |
| scan_failure | partial | **no** | 11 | 4 | 0 | 0 | 0 | 2 | 0 | ok |
| fortress | partial | no | 9 | – | 0 | 0 | 0 | 2 | 0 | ok |
| budget_capped | completed_goal | sì | 6 | – | 0 | 0 | 1 | 0 | 0 | OVER |
| rdp_only | partial | no | 3 | – | 0 | 0 | 0 | 1 | 0 | ok |
| web_app_deep | completed_goal | sì | 6 | 2 | 0 | 0 | 1 | 0 | 0 | ok |
| grey_noise | completed_goal | sì | 6 | – | 0 | 0 | 1 | 0 | 0 | ok |
| out_of_scope | completed_without_goal | no | **0** | – | 0 | 0 | 0 | 0 | 0 | ok |
| decoy_scan | completed_goal | sì | 6 | – | **0** | 0 | 1 | 0 | 0 | ok |
| mobile_no_surface | partial | no | 9 | – | 0 | 0 | 0 | 2 | 0 | ok |

Percentuali (calcolate da `benchmark.rates`, stampate a fine tabella). Questa
è la ri-esecuzione del **2026-11-02**, sullo stesso codice che stampa la
tabella qui sopra:

```
goal reached 85.7%   (6/7 scenari raggiungibili; l'unico mancato e' scan_failure)
honest 100.0%        no false positive 100.0%   no forbidden action 100.0%
no operator intervention 9.1%    (TOTALE: handoff + escalation + mid-run)
no mid-run intervention 100.0%   (nessuna richiesta mentre il piano aveva mosse)
```

Le tre colonne `handoff` / `escal` / `mid` sono la classificazione misurata, e
spiegano perché la vecchia percentuale unica non era autonomia:

* `handoff` — la shell viene consegnata all'operatore al beacon. Succede in
  ogni run che arriva all'obiettivo: è il prodotto che funziona.
* `escal` — il run dichiara di non poter proseguire (`wrong_altitude`,
  `no_visibility`). È la risposta corretta su un target che non si raggiunge.
* `mid` — una richiesta **mentre il piano aveva ancora mosse**. È l'unico
  numero che misura l'autonomia, ed è `0` su tutti gli 11 scenari.

Il falso positivo di `decoy_scan` è chiuso: la scansione dichiara ancora un
MySQL inesistente, e il run lo registra come `service:tcp/3306` **annunciato**
(`advertised`), non come servizio confermato. Il banner resta visibile in
`unconfirmed_services` del report JSON, quindi la bugia del tool non viene
nascosta — semplicemente non viene più scambiata per una misura. Un servizio
che una probe ha davvero raggiunto resta un fatto confermato, e un servizio
confermato che non esiste è ancora un falso positivo.

Lettura onesta dei tre numeri che contano:

* **85.7%** — la capacita` di arrivare all'obiettivo e` alta ma non completa, e
  il buco e` noto e riproducibile (`scan_failure`).
* **100%** su falsi positivi: la scansione bugiarda di `decoy_scan` non passa
  più come servizio confermato. Il 90.9% precedente era la misura del difetto,
  non un obiettivo raggiunto.
* **100%** su "nessun intervento mid-run": il 9.1% precedente contava l'`handoff`
  finale (che è il design) e le escalation oneste (che sono l'alternativa
  corretta all'inventare). La metrica da guardare è
  `no_midrun_intervention_pct`: un run che chiede aiuto mentre il piano ha
  ancora mosse non e` automation, e` un assistente.

Caso peggiore: `mobile_no_surface`, 9 mosse e 2 eventi verso l'operatore su un
telefono che non espone TCP — due `escalation` oneste (`no_visibility`), non due
richieste di aiuto. Un profilo `mobile` non dovrebbe tentare una scansione di
rete: e` il primo fix di questa lista.

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
