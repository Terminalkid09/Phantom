# Phantom — Roadmap di lavoro (audit consolidato)

**Commit di riferimento:** `f6771f55967e4d0d33c5c3536316736946dbaea3` (branch `dev`)
**Fonti verificate:** `docs/Phantom_dev_audit.md` (Manus #1), `docs/master_review.md` (Manus #2 — **fa fede dove discorda**), verifica indipendente Buffy.
**Data creazione:** 2026-09-13

---

## COME USARE QUESTO FILE (regole anti-allucinazione)

1. **Prima di toccare un item**, apri il file:linea indicato in `Evidenza` e ricontrolla che il codice sia ancora così (il branch cambia).
2. **Un item si segna `[x]` SOLO se**: modifica fatta + test relativo verde + comando di verifica della sezione eseguito.
3. **Mai cancellare item**: se un item diventa non applicabile, si segna `~~obbliato~~` con motivazione nel Log.
4. Ogni sessione di lavoro finisce con una riga nel **Log di avanzamento** in fondo (data, item, commit).
5. Non ridefinire requisiti o decisioni: sono già fissati nella sezione **Decisioni vincolanti**.
6. Se durante il lavoro emerge un finding nuovo, si aggiunge alla sezione del suo dominio con id `X-##` progressivo.
7. Estado: `[ ]` da fare · `[~]` in corso (annotare nel Log) · `[x]` fatto e verificato.

---

## Decisioni vincolanti (da master_review + proprietario — NON rinnovare il dibattito)

| # | Decisione | Conseguenza |
|---|---|---|
| D-1 | Il numero di feature del C2 **non è un problema**. Il problema è la separazione control/capability/authorization/artifact plane. | Non si rimuovono feature; si separano i piani. |
| D-2 | La remote session **mantiene mouse+tastiera** (input reale). Non esiste l'opzione "view-only default". | Lavorare su token/expiry/revoca/audit, non sulla riduzione. |
| D-3 | Il beacon non rilevato da McAfee nel test del proprietario è **evidenza empirica del test specifico**, non garanzia generalizzata. | Nessuna affermazione di detection/imunità senza prova; si valuta compatibilità, failure handling, cleanup. |
| D-4 | Auto-persist al check-in: **decide il proprietario** (tenere documentato vs. gate dietro config). Fino a decisione: item P0-2 resta aperto. | Non rimuovere in silenzio. |
| D-5 | Catch-all `/{tail:.*}` è **design malleable C2 intenzionale**, non bug. | Ciò che è bug è la mancanza di test matrice auth route×principal×method. |
| D-6 | `sandbox: false` (Electron) è un **trade-off da documentare+mitigare**, non finding autonomo. | contextIsolation, no nodeIntegration, CSP, IPC tipizzato. |
| D-7 | Priorità di correzione: prima **correttezza funzionale** (false success), poi confini, poi architettura, infine validazione enterprise. | L'ordine P0→P1→P2 qui sotto è vincolante. |
| D-8 | Metasploitable2 = **regression history**, non prova enterprise. La prova è la matrice P2. | Nessuna affermazione enterprise end-to-end prima della matrice. |

---

## Legenda severità (unificata dai 2 audit)

- **C** = confermato in codice su `f6771f5` · **S** = staticamente plausibile, da confermare al momento del fix
- **Bug** funzionale · **Sec** sicurezza/governance · **Hard** hardening · **Mat** maturità/validazione

---

# P0 — Correttezza e confini (prima release-blocker)

## P0-A. Manual core / chain planner

### P0-1 · `execute_step()` restituisce True anche su comando fallito [Bug, C] — **[x] 2026-09-13**
- **Evidenza:** `phantom/core/chain.py:147-178` — dopo `run_command()` interpreta i finding e ritorna `(True, ...)` a prescindere dall'exit code; nessuna distinzione `failed / no_findings / succeeded`.
- **Fix:** ritornare lo stato reale (exit code + output vuoto → `no_findings`); inglobare i finding solo su successo; esporre lo stato al chiamante.
- **Test di chiusura:** step con comando exit≠0 → `failed`; exit=0 senza finding → `no_findings`; exit=0 con finding → `succeeded` e WorldModel aggiornato.
- **Verifica:** `python -m pytest tests/ -q -k "chain or manual_core"`.

### P0-2 · Auto-persist al primo check-in — DECISO (Q-1): si TIEDE, documentato + audit entry [Sec/Governance, C] — **[x] 2026-09-13**
- **Evidenza:** `phantom/core/c2_server.py:124-135` (`update_beacon()` accoda `persist` incondizionato per ogni beacon nuovo; nessun manifest/grant/approval).
- **Decisione proprietario (Q-1):** comportamento mantenuto come default documentato; NON si gatea dietro config.
- **Fix applicato:** commento di documento nel codice (default deliberato, riferimento a Q-1 in questo file) + nuova audit entry immutabile `auto_persist_queued` (beacon_id, method, task_id) in catena HMAC subito dopo la coda del task; verificato live: `beacon_registered` → `auto_persist_queued`, `AuditLog.verify()` ok.
- **Test di chiusura:** check-in beacon nuovo → task `persist` in coda + audit entry in catena (test esistenti `test_c2.py::TestC2State` restano verdi).
- **Verifica:** `python -m pytest tests/ -q -k "c2 or audit"` + audit chain verify.

### P0-3 · `C2Server.start()` avvia il thread anche con porta occupata [Bug, C] — **[x] 2026-09-13**
- **Evidenza:** `phantom/core/c2_server.py:~1087-1097` — bind forzato in `_start_server()`, il thread muore con `OSError 10048` e il chiamante crede sia partito. (Finding proprio, nessuno dei 2 audit lo aveva.)
- **Fix:** fail-fast con errore riportato al chiamante (`bind_error`), come fa già il tracker.
- **Test di chiusura:** seconda istanza sulla stessa porta → errore sollevato/notificato, nessun thread zombie.
- **Verifica:** `python -m pytest tests/ -q -k "c2 and listener"`.

### P0-4 · Enrollment fail-closed su bind non-loopback [Sec, C] — **[x] 2026-09-13**
- **Evidenza:** `phantom/core/c2_server.py:64-75` — `authenticate_beacon()` ritorna `not beacon_auth_required()` per beacon non enrolled; `_start_server()` forza `bind_host = "0.0.0.0"` ignorando l'host configurato.
- **Fix:** (a) bind dell'host configurato con fail-fast (vedi P0-3); (b) se bind non-loopback e `PHANTOM_BEACON_AUTH_REQUIRED` unset → warning forte + fail-closed nel profilo production; enrollment one-time separato per il primo beacon.
- **Test di chiusura:** beacon non enrolled su listener non-localhost con profilo production → rifiutato; su loopback → permesso (compat lab).
- **Verifica:** `python -m pytest tests/ -q -k "beacon_auth"`.

## P0-B. Remote session

### P0-5 · Viewer `/send` senza autenticazione propria [Sec, C] — **[x] 2026-09-13**
- **Evidenza:** `phantom/core/remote_viewer.py:~215-226` — `POST /send` → `c2_state.queue_task(bid, cmd)` senza token/nonce/CSRF; loopback trattato come boundary. Nessun CSP.
- **Fix (preserva D-2):** session token random nella URL del viewer (una tantum), expiry breve, revoca; header check su tutte le rotte `/send|/frames|/frame`; CSP restrictiva.
- **Test di chiusura:** POST senza token → 401; token scaduto/revocato → rifiuto; con token → funziona.
- **Verifica:** `python -m pytest tests/ -q -k "remote"`.

### P0-6 · Polling frame sovrapposto + retention indefinita [Bug/Hard, C] — **[x] 2026-09-13**
- **Evidenza:** `phantom/core/remote_viewer.py:~117-134` — `setInterval(async …)` senza guardia di sovrapposizione; il "sync" è un `setInterval(() => {}, 60000)` **vuoto**; intervallo calcolato solo alla creazione.
- **Fix:** polling seriale con cursor/sequence + AbortController; TTL/cleanup frame su chiusura sessione; quota per beacon.
- **Test di chiusura:** nessuna richiesta sovrapposta (log/test); frame più vecchi del TTL rimossi.
- **Verifica:** `python -m pytest tests/ -q -k "remote_viewer or frames"`.

### P0-7 · Session expiry/revoke non raggiunge il modulo [Sec, C] — **[x] 2026-09-13**
- **Evidenza:** il modulo scaricato dal beacon non riceve revoca (audit F-23). Task string in-band (`remote input …`) senza capability separata.
- **Fix:** task di sessione con `session_id`, `expires_at`, `revoke`; il modulo rispetta la revoca; capability separate `remote.view|mouse|keyboard|clipboard|file` (solo tipizzazione/autorizzazione, funzione invariata — D-2).
- **Test di chiusura:** revoke → il modulo smette input entro il grace; expiry scaduto → rifiuto.
- **Verifica:** `python -m pytest tests/ -q -k "remote_module or remote_session"`.

## P0-C. C2 auth/transport

### P0-8 · Nonce HMAC solo in RAM (replay dopo restart) [Sec, C] — **[x] 2026-09-13**
- **Evidenza:** `phantom/core/c2_server.py:59-104` — `auth_nonces` dict in memoria; counter advisory; commento ammette il trade-off.
- **Fix:** server epoch invalidante al boot (nonce store persistito o `epoch_id` nell'auth: nonce di epoch precedente rifiutato); idempotenza task via `task_id`.
- **Test di chiusura:** replay di una request firmata dopo restart → rifiutata/stale.
- **Verifica:** `python -m pytest tests/ -q -k "auth or replay"`.

### P0-9 · Token payload in query string `?auth=` [Sec, C] — **[x] 2026-09-13**
- **Evidenza:** `phantom/core/c2_server.py:734,740,806,825` + `phantom/payloads/beacon/src/main.cpp:825-833` — token globale condiviso su tutti gli endpoint payload, incorporato negli URL del beacon.
- **Fix:** header one-time / token scoped per endpoint+platform, short-lived; rifiuto progressivo del query-token (fallback finché il parco beacon non è migrato); redazione URL nei log.
- **Test di chiusura:** query token in profilo production → rifiuto; header token → ok; log senza token.
- **Verifica:** `python -m pytest tests/ -q -k "payload or c2"`.

### P0-10 · Matrice di autorizzazione route×principal×method assente [Hard, C] — **[x] 2026-09-13**
- **Evidenza:** `c2_server.py:_setup_app()` (~1027-1065) — route operator (`/api/v1/*`) protette solo se `API_TOKEN` impostato e solo su 3 path (`api_auth_middleware`, ~534-543); catch-all affidato a check per-handler.
- **Fix:** middleware centrale con principal (beacon/operator/artifact) e matrice esplicita; test di matrice.
- **Test di chiusura:** per ogni route: anonimo/beacon/operator × GET/POST → esito atteso tabellare.
- **Verifica:** `python -m pytest tests/ -q -k "auth_matrix or c2"`.

## P0-D. Reproducibilità

### P0-11 · Suite non installabile in modo deterministico [Mat, C] — **[x] 2026-09-13**
- **Evidenza:** `requirements.txt` senza lock/versions pinned per dev; CI installa ad-hoc (`.github/workflows/ci.yml:26,193`); raccolta mira si fermava su `ModuleNotFoundError: No module named 'rich'` (audit #2 §15.7).
- **Fix:** `requirements-dev.txt` (o lock) con pytest+plugin+deps test; step CI "pip install -r requirements-dev.txt".
- **Test di chiusura:** macchina pulita (venv nuovo) → collect-only completo senza import error.
- **Verifica:** `pip install -r requirements-dev.txt && python -m pytest --collect-only -q | tail -3`.

### P0-12 · CI: drift dell'elenco esplicito dei test [Mat, C] — **[x] 2026-09-13**
- **Evidenza:** `.github/workflows/ci.yml:41-42` — lista TEST_FILES hard-coded: un file nuovo non viene mai girato in CI. (Finding proprio.)
- **Fix:** raccolta via glob `tests/test_*.py` (escludendo gli script standalone in `collect_ignore`) + step di drift-check.
- **Test di chiusura:** aggiungere file fittizio → CI lo esegue; rimuoverlo → nessun fallimento.
- **Verifica:** workflow file aggiornato + run locale dello stesso glob.

---

# P1 — Architettura enterprise

## P1-A. Task tipizzati e capability grant

### P1-1 · Task string arbitrarie end-to-end [Sec, C] — **[x] 2026-09-13**
- **Evidenza:** `C2State.queue_task` (dict con `command` stringa) → `phantom/api/server.py:328-336` → dispatcher beacon. L'auth prova chi ha inviato la stringa, non che la capability sia autorizzata.
- **Fix:** schema task tipizzato `{task_id, capability_id, args, scope_ref, expires_at, policy_hash}` + adapter compat esplicito per stringhe legacy; deny-by-default fuori manifest.
- **Test:** task string legacy fuori adapter → rifiuto; task tipizzata con capability assente dal manifest → rifiuto.
- **Verifica:** `python -m pytest tests/ -q -k "task"`.

### P1-2 · Whitelist advisor contiene capability sensibili [Sec/Governance, C] — **[x] 2026-09-13**
- **Evidenza:** `phantom/automation/llm_advisor.py:46-56` — `_ADVISABLE` include `rce_foothold`, `dc_sync`, `lateral_pivot`, `kerberoast`, `as_rep_roast`. (Rafforzamento mio del F-16: l'advisor "non-gating" può comunque spingerle nel ranking.)
- **Fix:** whitelist per profilo engagement (lab/research/engagement); capability sensibili fuori dal default; decision record della policy.
- **Test:** profilo default → suggerimento sensibile ignorato.
- **Verifica:** `python -m pytest tests/ -q -k "advisor or llm"`.

## P1-B. Evolution engine

### P1-3 · Stato non atomico e non process-safe [Sec, C] — **[x] 2026-09-13**
- **Evidenza:** `phantom/automation/evolution/loop.py:56-121` — `EvolutionState` con `read_text`/`write_text`, niente lock/temp+replace/fsync/CAS.
- **Fix:** temp-file+`os.replace`+lock inter-processo (o SQLite); schema version; recovery post-crash.
- **Test:** due writer concorrenti → nessuna perdita; crash durante save → stato valido.
- **Verifica:** `python -m pytest tests/ -q -k "evolution"`.

### P1-4 · Budget gate riservato dopo l'esecuzione [Sec, C] — **[x] 2026-09-13**
- **Evidenza:** `loop.py:~173-217` — `can_gate()` prima dello spawn, `count_gate()` a worker finito → over-admission con più worker.
- **Fix:** `reserve_gate_slot()` atomico prima dello spawn; rilascio su failure; limite simultaneo worker.
- **Test:** N pattern > budget → spawn ≤ budget anche concorrenti.
- **Verifica:** come P1-3.

### P1-5 · Pinning per job assente [Sec, C] — **[x] 2026-09-13**
- **Evidenza:** `loop.py` — nessun `engine_commit/knowledge_version/policy_version/registry_digest` fissato all'avvio; le proposte diventano disponibili al run corrente (F-17).
- **Fix:** job record con digest; proposte disponibili solo a run successivi dopo review/merge/canary.
- **Test:** capability appresa a run in corso → non usata dal run corrente.
- **Verifica:** `python -m pytest tests/ -q -k "evolution or learned"`.

### P1-6 · Token GitHub nell'URL git [Sec, C] — **[x] 2026-09-13**
- **Evidenza:** `phantom/automation/evolution/publish.py:126` — `https://x-access-token:TOKEN@github.com/`.
- **Fix:** `http.extraHeader` / credential helper temporaneo / token di installazione GitHub App; pulizia contesto.
- **Test:** nessun token in `git config`/process list/errori (grep sul run).
- **Verifica:** `python -m pytest tests/ -q -k "publish"`.

### P1-7 · Beta loader: check esistenza, non digest della candidate [Sec, C] — **[x] 2026-09-13**
- **Evidenza:** `phantom/automation/evolution/beta.py:48-99,147-157` — carica PR aperte `auto-evolution/*` e le importa in-process; `_gate_in_checkout` verifica che esista *una* capability learned, non *quella* candidata col digest verificato.
- **Fix:** digest esatto del file candidate; verifica commit/repo/author trust/review status; import in worker subprocess (vedi P1-8).
- **Test:** PR con ID≠file candidate → rifiutata; digest cambiato dopo gate → load rifiutato.
- **Verifica:** `python -m pytest tests/ -q -k "beta or evolution"`.

### P1-8 · Import di codice machine-authored nel processo principale [Sec, C] — **[x] 2026-09-13**
- **Evidenza:** `phantom/automation/guidance/learned/__init__.py:37-64` — `load_learned()` importa *tutto* al boot nel processo principale; il gate AST (`evolution/gate.py:44` "stdlib is fine wholesale") è validazione, non sandbox (F-13).
- **Fix:** esecuzione learned in worker/container separato con egress deny + FS read-only + resource limits; il processo principale usa solo capability firmate/promosse; il gate resta layer aggiuntivo.
- **Test:** capability learned con `subprocess`/socket non allowlist → bloccata a runtime nel worker.
- **Verifica:** `python -m pytest tests/ -q -k "learned or gate"`.

## P1-C. Dati, secret, artifact

### P1-9 · Redaction regex-only [Sec, C] — **[x] 2026-09-13**
- **Evidenza:** `phantom/automation/llm_advisor.py:138-160` (`redact()`); sandbox usa solo questo choke point (`evolution/sandbox.py:87`).
- **Fix (v2):** schema-based redaction per campo classificato + entropy scan + pattern base64/multilinea/nested JSON; test adversarial (JSON annidato, YAML, URL-encoding, base64, multilinea).
- **Test:** canary secret in nessun output verso remote provider.
- **Verifica:** `python -m pytest tests/ -q -k "redact or advisor"`.

### P1-10 · Credenziali/OTP trattati come campi normali [Sec, C] — **[x] 2026-09-13**
- **Evidenza:** `phantom/automation/social/aitm.py:84-86,238-242` (estrazione `{username,password,otp}`) → `phantom/automation/social/tracker.py:482-502,985-1000` (`record_cred` in ledger in memoria). Nessun tipo "non persistibile" prima dell'event bus.
- **Fix:** tipi non-persistibili per password/otp/cookie/token; redazione prima dell'event bus (non solo in view); test canary end-to-end (event bus, C2 result, artifact, report, PR).
- **Test:** canary password/otp → assente da tutti gli output persistiti.
- **Verifica:** `python -m pytest tests/ -q -k "cred or canary or aitm"`.

### P1-11 · Artifact senza classification/TTL/quota per engagement [Sec, C] — **[x] 2026-09-13**
- **Evidenza:** `c2_server.py` — storage in `data/screenshots|remote|recordings|downloads`; limiti solo quantitativi (`MAX_RESULT_OUTPUT_BYTES`, `MAX_RESULTS_PER_BEACON`).
- **Fix:** `artifact_id`, engagement owner, classification, checksum, TTL, cleanup job, audit access/read/delete; rifiuto sopra quota.
- **Test:** artifact di beacon A non leggibile da engagement B; TTL scaduto → cleanup.
- **Verifica:** `python -m pytest tests/ -q -k "artifact"`.

### P1-12 · Report HTML senza escaping [Hard, C] — **[x] 2026-09-13**
- **Evidenza:** `phantom/modules/report.py:656-685` (`_build_vuln_html`): interpolazione diretta di `cve.description`, `svc_name`; `html.escape` usato **0 volte** nel file.
- **Fix:** escaping in serializzazione per tutti i campi interpellati; anche `.pm` export/ findings history redatti (P1-9).
- **Test:** description con `<script>` → escaped nell'HTML esportato.
- **Verifica:** `python -m pytest tests/ -q -k "report"`.

## P1-D. Electron

### P1-13 · IPC generico non tipizzato [Sec, C] — **[x] 2026-09-13**
- **Evidenza:** `electron/electron/preload.ts:22-23` (`request(method, endpoint, body)` generico) + `electron/electron/main.ts:207` (`api-request` inoltra tutto). Mitigazioni esistenti: bearer solo nel main, readiness-wait, AbortController 2h.
- **Fix (D-6):** endpoint allowlist nel handler `api-request` + convenience API tipizzate; separazione read-only/mutating; schema validation sui body.
- **Test:** IPC con endpoint non allowlistato → rifiutato dal main.
- **Verifica:** `cd electron && npx tsc --noEmit && npm test` (se presente) + smoke manuale.

### P1-14 · Stati UI incompleti e polling sovrapposto [Bug, S] — **[x] 2026-09-13**
- **Evidenza:** pannelli AutoMode/C2/remote: nessun sequence/abort/reconnect condiviso; `running` non distingue planning/waiting-approval/active/stopping/failed (F-26).
- **Fix:** stati terminali espliciti, AbortController, dedup, reconnect.
- **Verifica:** come P1-13.

## P1-E. AD graph

### P1-15 · AD graph: arricchire prima di ambire a BloodHound [Mat, C] — **[x] 2026-09-13**
- **Evidenza:** `phantom/core/ad_graph.py` — nodi domain/user/group/computer/DC, edge member_of/admin_to/session/cracked/owns, BFS depth-8. Manca: ACL/ACE (GenericAll, WriteDACL, AddMember, DCSync, deleghe), GPO/trust, provenance (SID, collected_at, confidence), scala (JSON+BFS).
- **Fix:** edge ACL/delegation con provenance e freshness; schema con `source/collected_at/confidence`; poi decidere import SharpHound (domanda Q-3).
- **Test:** path correctness su fixture con ACL nota; false-path detection.
- **Verifica:** `python -m pytest tests/ -q -k "ad_graph"`.

---

# P2 — Validazione enterprise (master §14/§16)

### P2-1 · Classificazione capability [Mat] — **[x] 2026-09-13**
Taggare ogni capability nel registry: `shell_command` / `in_process_engine` / `marker_only` / `lab_only` / `not_validated`.
- **Fatto:** campo `exec_class` su Capability (default `shell_command`); i 4 motori in-process onesti (`hunt_web`, `idor_scan`, `web_creds`, `differential_analysis`) sono taggati `in_process_engine` in kit.py; test di distribuzione (test_p2_classification.py) blocca regressioni. La matrice di validazione usa questo campo come chiave.
Taggare ogni capability nel registry: `shell_command` / `in_process_engine` / `marker_only` / `lab_only` / `not_validated`.
- **Nota già verificata:** `_idor_adapter` e `_hunt_web_adapter` (`guidance/kit.py:2652-2656,2692-2696`) sono marker stub in-process onesti e documentati — non contarli come shell capability.

### P2-2 · Matrice scenari (da master §14) — **seed popolato 2026-09-13**
| Scenario | Codice | Lab | Integration | Runtime | Gap |
|---|---|---|---|---|---|
| Windows 11 | sì (beacon) | parziale (VM manuale) | no | parziale (test owner) | build CI + firma |
| Defender/EDR lab | sì (edrcheck/edr-kill) | no | no | sì (owner, McAfee) | lab EDR automatizzato |
| Linux systemd | sì (persist) | sì (compose) | sì | parziale | boot-resume test |
| macOS permissions | no | no | no | no | porting beacon |
| AD nested groups | sì (ad_graph BFS depth-8) | parziale | sì (unit) | no | lab AD reale |
| AD ACL/delegation | sì (P1-15 edge+provenance) | no | sì (unit) | no | fixture ACL reale |
| Entra ID / hybrid | no | no | no | no | non iniziato |
| AWS/Azure/GCP | sì (cloud_* adapters) | parziale (moto-style) | sì (unit) | no | lab cloud |
| Kubernetes | parziale (k8s_escape) | no | sì (unit) | no | cluster lab |
| NAT/proxy/TLS inspection | sì (proxy.h, egress) | parziale | no | no | test proxy reale |
| IPv4/IPv6 | parziale | no | no | no | dual-stack scan |
| WAF/API gateway | sì (waf_blocked cause → evolution) | sì (lab WAF) | sì | parziale | più fixture WAF |
| Segmentazione rete | sì (scope engine) | parziale | no | no | test multi-segmento |
| Packet loss/clock skew | sì (lease/retry C2) | no | sì (resilience) | no | chaos test |
| Remote input stress | sì (remote module) | no | parziale | no | soak test input |
| Evolution replay | sì (P1-3/4/5/7) | sì (lab compose) | sì | no | replay deterministico |

**Lettura:** le colonne Lab/Integration sono la roadmap di test enterprise; Runtime = prove raccolte su macchine reali autorizzate (owner).
|---|---|---|---|---|---|
| Windows 11 | | | | | |
| Defender/EDR lab | | | | | |
| Linux systemd | | | | | |
| macOS permissions | | | | | |
| AD nested groups | | | | | |
| AD ACL/delegation | | | | | |
| Entra ID / hybrid | | | | | |
| AWS/Azure/GCP | | | | | |
| Kubernetes | | | | | |
| NAT/proxy/TLS inspection | | | | | |
| IPv4/IPv6 | | | | | |
| WAF/API gateway | | | | | |
| Segmentazione rete | | | | | |
| Packet loss/clock skew | | | | | |
| Remote input stress | | | | | |
| Evolution replay | | | | | |

Metriche: coverage, FP, FN, riproducibilità, time-to-evidence, detection latency, cleanup success, scope violations, review burden.

### P2-3 · Test negativi di autorizzazione (obbligatori per release) — **[x] verificati 2026-09-13**
- beacon non enrolled rifiutato su non-localhost (P0-4) → `test_unenrolled_refused_on_non_loopback`
- auto-persist accodato SOLO con audit entry `auto_persist_queued` (P0-2, decisione Q-1) → `test_auto_persist_queues_audit_entry`
- task string non autorizzata rifiutata (P1-1) → `test_legacy_unknown_verb_denied`, `test_grant_manifest_restricts_beacon`, `test_queue_task_raises_policy_error`
- replay dopo restart rifiutato (P0-8) → `test_stale_epoch_nonce_refused`
- payload token: header accettato, query deprecato (P0-9) → `test_payload_header_token_accepted`
- remote input senza session token rifiutato (P0-5) → `test_viewer_send_requires_token`, `test_viewer_data_routes_require_token`
- expiry revoca input e stream (P0-7) → modulo C rispetta deadline/revoca; `test_viewer_expiry_refuses`
- artifact cross-engagement isolati + TTL/quota (P1-11) → `test_cleanup_expired_deletes_and_receipts`, `test_over_quota_blocks_when_dir_full`
- evolution budget atomico (P1-4) → `test_concurrent_gate_reservation_never_over_admits`
- beta PR con digest diverso rifiutata (P1-7) → `test_beta_candidate_digest_mismatch_refused`
- learned module in subprocess con tree-kill (P1-8) → `test_learned_worker_timeout_kills`, `test_learned_worker_missing_module`
- execute_step exit≠0 → failed (P0-1) → `test_execute_quiet_reports_nonzero_exit` + batch test_p0_hardening
- canary secret assente da ogni output (P1-9/P1-10) → `test_secret_survives_repr_str_and_json`, `test_cred_and_session_dicts_are_non_persistible`, `test_vuln_and_service_html_escapes_target_data`

Item residui (da eseguire quando il pezzo corrispondente esisterà): preview digest ≠ execution (dipende dal planner congelato — nota P0-1); SCOPE: hostname A/AAAA e DNS rebinding (P1 scope item non ancora aperto).

---

# Domande aperte (gating per design P1 — risponde il proprietario)

1. **Q-1** Auto-persist: si tiene (documentato) o si gatea? → blocca P0-2.
2. **Q-2** Multi-operatore/multi-engagement è un obiettivo reale o single-operator? → determina profondità dell'isolamento (P1-11, P1-13).
3. **Q-3** AD graph: un giorno importa SharpHound JSON reale o resta Phantom-native? → P1-15.
4. **Q-4** Dati che possono lasciare la macchina verso il cloud LLM: la policy attuale "testo di reasoning redatto" è quella finale? → P1-9.
5. **Q-5** Retention per screenshot/recording/audio/GPS/download? → P1-11.

---

# Fase R/C — reasoning adattivo e modello a cellule (auto-mode v3)

**Contesto.** Le fasi P0/P1/P2 hanno chiuso correttezza, sicurezza e confini. Restava il limite che l'operatore ha indicato come il vero problema: l'auto-mode decideva con **una sola formula fissa** — `priority = (1-risk)/opsec_cost x prior` (`agent.py:_priority`) — e l'aria di "ragionamento" era confinata al `ReasoningEngine`, che però deduce senza entrare nella scelta. Le celle/stage esistono (`phases/`), ma i ruoli sono `if workers >= N` hardcoded e l'orchestratore è un **drenatore di azioni**, non un decisore.

**Decisioni vincolanti dell'operatore (approvate in sessione):**

| # | Decisione |
|---|---|
| D-R1 | I pesi delle lenti si adattano **a eventi** (stall, noise breaker, foothold, stadio, visibility), mai in continuo: una decisione deve essere riproducibile da uno STATO, non da un orologio. |
| D-R2 | Il **veto stealth è hard** sopra soglia, ma **stretto** (solo aggressive/forceful/high-detection): ferma la mossa marginale, non congela un run senza alternative. |
| D-R3 | Il guadagno informativo scavalca l'EV **solo a ipotesi incerte**: il bonus è una frazione del valore della mossa, quindi per costruzione può ribaltare solo un divario più stretto della banda. |
| D-R4 | Il **bandit muove i pesi solo cross-engagement**, con tetto (±25% sul peso stealth) e solo con entrambi i campioni presenti. |
| D-C1 | La concorrenza è una proprietà dell'**azione**, non del run: contatto nullo (OSINT/correlazione/reverse) parallelizza; il contatto col target è **serializzato**; solo `--aggressive` paga una seconda cellula agente. |
| D-C2 | Il secondo agente su una task che **tocca il target** è **advisory** (ragiona, non esegue): il parere non costa rumore. |
| D-C3 | La diversità si ottiene con **pesi + policy di ricerca + seed** diversi, non con la casualità. |
| D-C4 | Migrazione **graduale a sotto-fasi** con gate per fase; nessun big-bang. |

## R1 — Lenti adattive (retrofit) `[x]`
- [x] `brain/lenses.py`: 5 lenti (progress, success, evidence, stealth, collateral), `WorldSignals` costruito da eventi, `adapt_weights()` guidato da tabella `_ADAPTATIONS` leggibile, normalizzazione. Evidenza: `phantom/automation/brain/lenses.py`.
- [x] `ReasoningProfile` (objective + policy + seed + soglia di veto) + catalogo `balanced`/`stealth_first`/`evidence_first`/`force_first` + `adversarial_profile()` per il secondo parere; `choose_profile()` mappa i flag operatore (`speed` **non** abbassa la tolleranza al rumore).
- [x] Wire nell'agente: `arbiter`, `reasoning_profile`, `_goal_facts`, `_open_hypothesis_caps`, `_signals`, `search_policy()`, `_decision_for`; `_priority` resta l'EV (scala) e la modulazione è **limitata** `[0.60x, 1.40x]` → l'ordine kill-chain sopravvive.
- [x] Promozione dello **stall** a modalità: `StallClassifier` invocato in `_recover_stall`, verdict emesso (`stall` event) e usato da `arbiter.search_policy()` (breadth/depth/identity).
- [x] Flag `--reason {balanced,stealth_first,evidence_first,force_first}` su `phantom`, shell `auto` e passthrough fino a `run_autonomous`.
- [x] Test: `tests/test_reasoning_lenses.py` (30).

## R2 — Arbitro multi-lente + veto hard `[x]`
- [x] `Decision` con `driver`/`runner_up`/`contributions`/`signals` e `explain()`: ogni mossa è **spiegata** (quale lente l'ha decisa). Emesso nel `run` event (`driver`, `search_policy`).
- [x] Veto verificato **a esecuzione** (`_stealth_veto` in `_execute_capability`), non solo in pianificazione: nessun path dello scheduler può aggirarlo. Difensivo per contratto (agente senza arbiter = "nessun parere", non "via libera").
- [x] Soglia di veto per profilo (`stealth_first` veta a 0.70, `balanced` a 1.00, `force_first` a 1.60).
- [x] Test: soglia stretta, quieto mai vetato, modulazione dentro la banda, ordine kill-chain preservato.

## R3 — Guadagno informativo `[x]`
- [x] Bonus **bounded** (15% balanced, più largo per `evidence_first`, tetto 30%) applicato alla mossa che **discrimina un'ipotesi aperta**; una sola fonte del segnale (niente doppio conteggio con la lente evidence — bug trovato dai test).
- [x] Test: ribalta un near-tie (5%), **non** ribalta un chiaro leader (2x).

## C1 — Cellule + permesso di egress `[x]`
- [x] `brain/cells.py`: `CellSpec` (ruolo, obiettivo, stadio, contatto, categorie USABILI, kind VISIBILI, kind RIPORTABILI), libreria di 10 ruoli, `Cell`, `EgressPermit`, `CellTeam`, `MAX_PEERS_PER_ROLE`.
- [x] Knowledge scoping reale: la cellula recon può **riportare** `vuln_class`/`attack_path` e **non può** vedere né pianificare `rce_foothold`/`exploit_plan`/`creds`/`beacon` (`capability_ids(registry)` non contiene alcuna capability di categoria `exploit`).
- [x] Cap del team = **minimo** sulle classi di contatto presenti (bug reale trovato dai test: con `max()` un ruolo report senza contatto alzava il cap delle cellule recon).
- [x] Escalation: peer **advisory** per i ruoli che toccano il target, peer **agente** per i ruoli sandbox; guardia peer-storm (bug reale trovato dai test: i peer advisory non facevano crescere il contatore).
- [x] Test: `tests/test_cells_egress.py` (30).

## C2 — Roster brain nell'orchestratore `[x]`
- [x] `CellTeam` istanziato dal run: `brain/cell_runtime.py` costruisce roster + permesso + bus + tribunale da doctrine → stage, una volta sola al primo planning pass (`AutonomousAgent._ensure_cells`).
- [x] Orchestratore come **scheduler di cellule**: il run diventa `_exec_with_permit(step)` — routing della capability alla cellula che la possiede, `admit()`/`release()` sul permesso di egress, `escalate()` sul verdict di stall.
- [x] Bus request/response fra cellule (`brain/bus.py`) + arbitrato dei disaccordi (`brain/tribunal.py`: vince l'evidenza verificata, il secondo parere ha un profilo avversariale).
- [x] Test: `tests/test_cells_runtime.py`.

## C3 — Sandbox di learning con triage + `--oM` `[x]`
- [x] Cellula di triage che confeziona il caso (firma, causa, tentativi, evidenza) — `brain/triage.py`.
- [x] `--oM` (only-markdown): PR di sola proposta `docs/evolution/<id>.md` (`evolution/proposal.py`), gate profile "proposal" (niente static/registry/units/lab) e **budget separato** dal budget delle capability (contatori `proposal_*` distinti in `EvolutionState`).
- [x] Test: `tests/test_evolution_proposal.py`.

## C4 — Sostituzione graduale del loop `[x]` (in corso per definizione)
- [x] Migrazione **per goal** con gate di copertura per classe di target; il vecchio loop resta il riferimento per ogni goal non migrato, poi sparisce pezzo per pezzo.
- [x] Ledger verificato (`cells.MIGRATED_STAGES`): `complete_kill_chain, deliver, beacon, post_exploit, expand, lateral, identity, social, cloud, mobile, harvest, evasion`. Esclusi `ad`/`crack` perché su target identity-class lo stadio AD pretende `recon` mentre la chain identity vieta `footprint`.
- [x] Gate di copertura (`tests/test_stage_migration.py`): ogni goal migrato, su ognuna delle 6 classi (ip/domain/cidr/email/username/phone), pianifica verso categorie che i ruoli della copertura possiedono tutte.
- [x] Contratto behaviour-preserving provato end-to-end (`tests/test_cell_loop_e2e.py`): con il loop stretto acceso la SEQUENZA di capability e l'esito finale sono identici a quelli del loop vecchio, su chain network e identity, con 0 refusal.

### Tre bug reali trovati dal gate (non dalla review)
1. **Ledger inerte.** `_current_stage` è il GOAL del run, non uno stadio di chain: un ledger con `("footprint",)` non corrispondeva mai e il loop stretto era codice morto che sembrava acceso. Ora la vocabolario è "goal" ed è pinnato da un test.
2. **Due categorie senza proprietario.** `beacon_deploy` (categoria `beacon`) e `ssh_login` (categoria `creds`) non erano possedute da nessun ruolo → il loop stretto avrebbe rifiutato proprio le due capability che costituiscono "arrivare al beacon". Ora c'è un invariante di registry (nessuna categoria senza ruolo).
3. **Roster costruito solo sulla chain.** La chain network non contiene uno stadio `post`, quindi metà di un run deep non aveva proprietario; e una chain identity che harvesta un IP poi DEVE scansionare quell'indirizzo, ma la chain identity vieta `footprint` → `scan_tcp` rifiutato 11 volte e nessun beacon (misurato). Ora la copertura unisce chain + goal del run, e ogni goal beacon-bound porta con sé la copertura recon.

### Verifica di fase (R/C)
```
python -m pytest tests/test_reasoning_lenses.py tests/test_cells_egress.py \
                 tests/test_cells_runtime.py tests/test_stage_migration.py \
                 tests/test_cell_loop_e2e.py tests/test_evolution_proposal.py -q   # 136 passed
python -m pytest tests/test_automation*.py tests/test_automode*.py \
                 tests/test_agent*.py tests/test_brain*.py tests/test_planner*.py -q   # 615 passed
# resto della suite (batch, con le 2 esclusioni CI)
```
Risultato sessione: **2608 test verdi**, 2 skipped, 0 failure.

---

# Fase E — edge-aware doctrine e trasporto cieco

**Contesto.** Due bug di dottrina, non di codice mancante: (1) su un target dietro
CDN l'agente avrebbe scansionato **l'edge del provider** — rumore enorme,
risultati falsi, e nel caso peggiore un abuso di infrastruttura di terzi;
(2) il beacon aveva **un solo endpoint compilato, nessuna via per il proxy** e
un pin TLS di fatto inerte, cioè era irraggiungibile in ogni rete gestita e
non autenticava il peer.

## E3 — rilevazione edge + origin candidates `[x]`
- [x] `brain/edge.py`: `detect()` da CNAME, IP range dei provider, header, PTR;
  `provider_for_cname/ip/headers`; `EdgeVerdict`/`OriginCandidate`/`EdgeReport`;
  `origin_candidates()` (PTR, split-horizon, record storici, CT log, header di
  origine leakati) con provenienza e confidenza.
- [x] Fatti nel world model (`EDGE_FACT`, `EDGE_THRESHOLD`) e `best_origin(wm)`:
  l'evidence dell'edge e dei candidati è **dato**, non una variabile di run.

## E4 — guard + origine prima di ogni cosa TCP `[x]`
- [x] `_edge_guard(cap)` in `agent.py`: qualunque capability a contatto con
  l'edge del provider viene **rifiutata con motivo** (non silenziosamente
  ignorata) finché non esiste un origin credibile; il rifiuto è la prova che
  la dottrina ha morso.
- [x] `_run_origin_discovery()` + capability `origin_discovery` (categoria
  `recon`, **in-process**, exec_class dichiarata in P2-1) con adapter e
  interpreter che scrivono `origin_candidate`/`origin_host` nel wm.
- [x] Doctrine/planner: edge rilevato → discovery dell'origine **prima** di
  qualunque azione TCP sul target.
- [x] Test: `tests/test_edge_doctrine.py` (edge rilevato ⇒ nessuno scan
  sull'edge; origine trovata ⇒ il percorso si apre; classe di target
  invariata).

## E5 — trasporto beacon: ladder, proxy, pin `[x]`
- [x] **Ladder di endpoint**: `C2_HOSTS` + `seed_ladder()` / `prefer_endpoint()`
  / `on_failure()` / `on_success()` con `failover_after` e rotazione; un argv
  host **non** distrugge la ladder compilata.
- [x] **Postura proxy**: Windows `WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY`
  (PAC/WPAD) con override esplicito di `C2_PROXY`, niente più
  `NO_PROXY`; POSIX tunnel `CONNECT` con `proxy_from_env()` /
  `proxy_bypassed()`; macOS `CURLOPT_PROXY`.
- [x] **Pin indipendente da mTLS** (`BEACON_PIN_ENFORCED`): il fingerprint del
  leaf È la decisione, quindi vale anche contro il certificato self-signed del
  C2 (il vecchio callback rifiutava sempre, quindi il pin non veniva mai
  raggiunto).
- [x] **Risoluzione dual-stack**: `dial_tcp` con `getaddrinfo(AF_UNSPEC)` e
  tutta la lista degli indirizzi provata — `gethostbyname` era IPv4-only e
  usava solo `h_addr_list[0]`.
- [x] **Igiene di scrittura**: loop di scrittura completo (headers+body) su
  `SSL_write`/`send`; il body parzialmente scritto rompeva l'HMAC.
- [x] Probe generati (`c2_crypto.write_beacon_c2_config`) con sanitizzazione
  `_c2_literal` (un endpoint malformato viene **scartato**, non escapato) e
  plumbing da `builder.compile_beacon(hosts=..., proxy=...)` +
  `get_c2_fallbacks()/get_c2_proxy()`.
- [x] **Pin acceso nel build ORDINARIO**: `BEACON_SERVER_FINGERPRINT` era emesso
  solo sul path mTLS, quindi in ogni build normale il verifier era codice
  irraggiungibile e il peer non autenticato. Ora `c2_crypto.server_cert_fingerprint()`
  legge il certificato del C2 (lo stesso file che il listener carica) e
  `network.beacon_pin()` lo passa al builder; kill-switch esplicito
  `PHANTOM_BEACON_PIN=0` / `c2.pin=0` perché rigenerare il certificato invalida
  i beacon giì deployati (comportamento corretto, ma deve essere una scelta).
- [x] **Harness eseguito davvero**: `payloads/beacon/src/test_transport.cpp`
  compilato e lanciato in WSL (`OK — transport logic: ladder, rotation, proxy
  parsing, no_proxy all behave`); i test Python tengono gli invarianti del C++
  che l'interprete non può eseguire.
- [x] Test: `tests/test_beacon_transport.py` (24).

### Tre bug reali trovati dal gate (non dalla review)
1. **Guardia ipersensibile ai commenti.** `assertNotIn("gethostbyname", …)` e
   `assertNotIn("WINHTTP_ACCESS_TYPE_NO_PROXY", …)` scattavano sul **commento**
   che spiegava la rimozione: il test era insieme fragile e cieco (una riga di
   prosa poteva "superarlo" parlando dell'API viva). Ora le negative girano su
   codice con i commenti rimossi (`_strip_cpp_comments`).
2. **Stessa classe di bug in un altro TU.** `cdp_pivot.h` risolveva l'host del
   pivot con `gethostbyname` e `h_addr_list[0]` — IPv4-only, primo indirizzo
   soltanto. Ora `cdp_connect()` con `getaddrinfo(AF_UNSPEC)` e tutta la lista;
   l'invariante è esteso a **ogni** sorgente del beacon.
3. **Il pivot non compilava affatto fuori da Windows.** `launch_and_connect()`
   usava `Sleep(...)` mentre lo shim POSIX si fermava a `closesocket`: il TU
   `cdp_pivot.h` era compilabile solo su Windows. Ora c'è lo shim e il TU
   compila su Linux (verificato con `g++ -std=c++20 -fsyntax-only`).
4. **Ogni build forzava un rebuild completo.** I chiamanti decidevano
   `force_rebuild` confrontando l'INTERO header generato con quello su disco:
   dopo E5 quel confronto è sempre diverso (il builder aggiunge ladder, proxy
   e pin) → recompilazione forzata ad ogni build di payload, con il fast path
   di freschezza mai preso. Ora si confronta l'**endpoint** davvero bruciato
   nel binario (`beacon_config_endpoint`), che è l'unica cosa per cui un
   rebuild ha senso.
5. **Header generati tracciati/misti nel repo.** `c2_config.h` è tracciato
   mentre `beacon_auth.h`/`crypto_config.h`/`build_id.h` no: un header
   generato che dichiara *"do not edit manually"* e contiene il token payload
   + lo stager PowerShell in base64 non appartiene alla repository. Inoltre un
   header stale puó attivare mTLS in una build che non l'ha chiesto (visto
   nell'harness: fingerprint diverso dal pin nuovo). Il generatore ora usa
   `#ifndef` attorno al pin; l'igiene di `c2_config.h` è tracciata come
   decisione (vedi report).

### Verifica di fase (E)
```
python -m pytest tests/test_edge_doctrine.py tests/test_beacon_transport.py -q   # 24+ passed
python -m pytest tests/test_beacon_transport.py tests/test_edge_doctrine.py \
                 tests/test_stage_migration.py tests/test_cells_runtime.py \
                 tests/test_cells_egress.py tests/test_cell_loop_e2e.py \
                 tests/test_reasoning_lenses.py tests/test_evolution_proposal.py -q   # 192 passed
# WSL
cd phantom/payloads/beacon/src && g++ -std=c++20 -O1 -pthread -I. test_transport.cpp \
     -o /tmp/test_transport && /tmp/test_transport
```

---

# Risposte alle domande aperte
1. **Q-1** Auto-persist si tiene documentato e si sistema se ha problemi
2. **Q-2** Multi-operatore phantom ha solo il .pm che si condivide, però multi-egagement per più target si che c'è l'ha
3. **Q-3** Può anche importare SharpHound JSON reale
4. **Q-4** I dati che possono lasciare non devono essere dati del target anche se se usi --llm per forza deve leggere qualcosa per capire bene il contesto però senza la flag --llm non viene usato, poi si ci sta l'uso per l'evolution ma la i dati non so del target quando dell'operazione quindi cosa stava provando a fare e cosa è fallito e perchè quindi se magarici sono dati sensibili la tipo l'ip nel comando si può dare all'llm un dato fittizio fake solo per farlo continuare, tanto la la cosa che importa è il ragionamento per evolversi e non il dato
5. **Q-5** Direi farli durà 30 giorni 
---

# Log di avanzamento

_(una riga per sessione: data · item · commit · note)_

- 2026-09-13 · audit fresco round 2 (fix dei problemi aperti + critiche della review red team) · (commit dev) · A-1: esecuzione **argv-only** sulla superficie operatore — nuovo `phantom/core/safe_exec.py` (parse quote-aware in argv, pipe/`;`/`&&`/`||` cablati nativamente, redirect ammessi solo `2>/dev/null` e `2>&1`, rifiuto di `$()/`` ``)/${}`), `BackendDispatcher.run_pipeline()` esegue con `shell=False` (nativo) o ri-serializza con quoting per token (WSL2 `bash -lc` / ssh), i 3 endpoint API usano `run_pipeline`, e `_validate_backend_command` condivide lo stesso parser del executor. A-2: le learned capability non vengono più importate nel processo principale — `learned/descriptor.py` legge il metadata in un subprocess con env `PHANTOM_*` rimosso, `Capability` ricostruita **senza adapter/interpreter**, `requires=[...]` dichiarativo per il planner, e il worker esegue adapter+interpreter+precondizioni reali restituendo i finding come dati (`run_learned_task`). A-3: CORS non più `*` (solo origin del renderer locale + `null`), Electron `sandbox: true` (preload CJS usa solo `electron`), `setWindowOpenHandler` deny + guard su `will-navigate`. A-6: `HitStore` con cap (2000 eventi/codice, 500 cred/sessione, 5000 codici). A-7: `VmBackend.run_sample` senza shell (argv + shlex). Review-3: sessione remota con token proprio che scade e si revoca (`issue/check/revoke_remote_session`, `remote-expire now` brucia anche il grant di delivery, dropper con `rs=` invece del token payload globale, `PHANTOM_REMOTE_STRICT` per rifiutare il path legacy). Review-4: auto-persist = grant di engagement (`c2.auto_persist` / `PHANTOM_AUTO_PERSIST`, default ON come Q-1, con audit `auto_persist_skipped`). Lab cloud: `lab/cloud/` (LocalStack+IMDS mock+Azurite+MinIO, seed di ruolo over-privilegiato/chiave leakata/bucket) **avviato e verificato** (IMDS v1+v2, seed IAM/S3 confermato) + `cloud/k8s/` (kind/k3d + scenario RBAC). In pi— pista: rimossa ogni path di esecuzione via shell dal dispatcher API (`_run_legacy_shell` eliminato), i listener in background di `handler` (msfconsole/nc/ncat) e l'auto-deauth di `wifi` ora usano argv con validazione di porta/payload/iface, `run_local` fa tree-kill sui timeout e manda lo stderr dei segmenti intermedi a DEVNULL (niente deadlock su pipe piene). Nuovi test: `tests/test_security_sweep_round2.py` (24).

- 2026-09-13 · audit fresco (sweep sicurezza fuori roadmap) · (commit dev) · trovati e corretti: (a) gate comandi API validava solo il PRIMO token → `nmap x; rm -rf ~` passava ed era eseguito con shell=True: ora `_split_shell_segments()` valida OGNI segmento fuori-quote e rifiuta sostituzione di comando (`$()`, `${}`, backtick); 0 regressioni sulle 42 comandi pubblicati dai moduli; (b) confronti token non timing-safe (API bearer, `X-Api-Token` C2, payload token, stager android, PIC) → `hmac.compare_digest`; (c) `TypedTask.is_expired()` andava in TypeError su deadline ISO/misto dal wire → coercizione + fail-closed su deadline non parsabile; (d) listener tracker pubblico leggeva `Content-Length` arbitrario (DoS memoria su server di phishing esposto) → clamp 64 KiB + `ValueError` gestito. Nuovo file `tests/test_security_sweep.py` (22 test). Verifica: security_sweep + api + api_auth + pm_api + manual_core + c2 + beacon_auth_server + remote_module + tracker/social/craft = verdi.

- 2026-09-13 · P2-1, P2-2, P2-3 (fase P2 completa) · (commit dev) · P2-1: campo `exec_class` su Capability + tag espliciti sui 4 motori in-process (hunt_web/idor_scan/web_creds/differential_analysis) + test distribuzione. P2-2: matrice scenari 16 righe popolata con stato reale (codice/lab/integration/runtime/gap). P2-3: checklist test negativi verificata 1:1 con i test esistenti + 2 test aggiunti (auto-persist audit entry, beta digest mismatch). Verifica: test_p2_classification + test_p1_* + audit/c2/guidance = 146 passed.

- 2026-09-13 · P1-1…P1-15 (fase P1 completa) · (commit dev) · P1-1: task policy tipizzate (task_policy.py, BEACON_VERBS speculare al dispatcher, grant manifest per beacon, deny-by-default, BeaconSession.task degrada a `shell <cmd>` per le OS one-liner — fix del false "no C2 session"). P1-2: profili advisor default/engagement/redteam (dc_sync/kerberoast/as_rep fuori dal default). P1-3/P1-4: EvolutionState atomico (temp+os.replace+fsync, lock inter-processo msvcrt/fcntl, schema_version) + reserve_gate_slot()/reserve_pr_slot() atomici (24 claim concorrenti → esattamente il budget). P1-5: job pin (engine_commit/knowledge_version/policy_version/registry_digest) emesso a run start e nel risultato. P1-6: push via http.extraHeader (token fuori da URL/argv), fallback con redazione nel messaggio. P1-7: beta loader con identity check (id=learned.* + firma del branch nel nome file + digest del body PR o marker di review). P1-8: learned worker subprocess isolato (fresh interpreter, tree-kill timeout, output cap) + source_module stampato dal loader. P1-9: redaction v2 (JWT-shaped + base64 a soglia entropia 4.5, tipo Secret). P1-10: Secret non-persistibile su cred/session dict, shell view come unica superficie di reveal. P1-11: artifact_policy.py (classificazione per directory, TTL 30g default da Q-5 — 7g per stream transienti, quota per directory, cleanup con receipt audit, metadata class/expires_days nell'API). P1-12: escaping HTML completo nel client report (vuln/services/analyzer/notes/target). P1-13: endpoint allowlist IPC in main (endpoint_allowlist.ts, read-only vs mutating, rifiuto 403 in-process). P1-14: run_state esplicita (starting/active/stopping/done/failed) + polling seriale con busy-guard + dedup log. P1-15: edge ACL/delegation BloodHound-grade (generic_all/write_dacl/write_owner/add_member/all_extended/force_change_password/dcsync/allowed_to_delegate/addspn/shadow_credentials/has_session) con provenance (source+confidence+collected_at, upgrade su fonte più forte) e ingest ad_acl. BONUS: tree-kill con process group su execute_quiet (timeout = nessun nipote orfano). Suite: 4 batch ≈ 2420 test verdi, 0 failure.

- 2026-09-13 · P0-4…P0-10 (fase P0 completa) · (commit dev) · P0-4: enrollment fail-closed su bind non-loopback (env `PHANTOM_ALLOW_OPEN_BEACON` per lab esplicito). P0-5: session token bearer su tutte le rotte dati del viewer + CSP + token in fragment. P0-6: polling seriale con AbortController + serial-guard. P0-7: remote session con `session_id`+`expires_at` (default 60s, scadenza servita nel payload del modulo) + comando `revoke`; il modulo rispetta deadline/revoca lato C. P0-8: epoch HMAC persistente (nonce cross-restart rifiutati). P0-9: token payload accettato da header `X-Phantom-Payload-Token` (query deprecato), log redatti. P0-10: matrice route×principal in middleware. Suite: test_p0_phase2 + test_remote_viewer aggiornati, verdi.

- 2026-09-13 · creazione roadmap da audit consolidato · — · baseline `f6771f5`, nessuna modifica al codice.
- 2026-09-13 · P0-1, P0-2, P0-3, P0-11, P0-12 · (commit dev) · P0-1: `chain.execute_step()` onesto su exit code (STEP FAILED / NO FINDINGS / STEP COMPLETED), finding ingeriti solo da exit 0, preview ed execution condividono `_build_shaped_command()`. P0-3: bind dell'host configurato + `bind_error` + `start()` che solleva RuntimeError (niente zombie thread). P0-2: auto-persist tenuto (Q-1) + audit entry `auto_persist_queued`. P0-11: `requirements-dev.txt` + CI su requirements-dev. P0-12: CI glob-based con esclusione esplicita dei 2 script standalone (`test_features_final.py`, `test_real_deploy.py` — il loro body fa sys.exit() all'import e `collect_ignore` non protegge un file passato esplicitamente). Bug corretto in itinere: docstring rotta in `chain.py` durante la stesura. Suite locale: batch 1-3 + stragglers ≈ 2428 test verdi + 12 subtest, collect-only 2372 pulito. Verifica finale completa (fresh venv + run CI su GitHub) alla prossima push.
- 2026-09-14 · R1, R2, R3, C1 (reasoning adattivo + modello a cellule) · (commit dev) · R1: nuovo `phantom/automation/brain/lenses.py` — 5 lenti (progress/success/evidence/stealth/collateral), `WorldSignals` derivato da eventi, `adapt_weights()` con tabella `_ADAPTATIONS` leggibile, `ReasoningProfile` + catalogo (balanced/stealth_first/evidence_first/force_first) + `adversarial_profile()` per la diversità. Wire in `agent.py`: `arbiter`/`reasoning_profile`/`_signals`/`search_policy()`/`_decision_for`; `_priority` resta l'EV come scala con modulazione limitata [0.60x,1.40x] (l'ordine kill-chain sopravvive, verificato). Promozione dello stall a MODALITÀ: `StallClassifier` invocato in `_recover_stall`, verdict emesso e usato per breadth/depth/identity. Flag `--reason` su `phantom`, shell `auto` e passthrough fino a `run_autonomous`. R2: `Decision` spiegata (driver/runner_up/contributions/signals + `explain()`), `driver` emesso nel `run` event, veto stealth **hard e stretto** verificato a ESECUZIONE (`_stealth_veto`) con soglia per profilo (0.70 stealth_first / 1.00 balanced / 1.60 force_first). R3: bonus info-gain bounded (15% balanced, tetto 30%) applicato solo a chi discrimina un'ipotesi aperta — una sola fonte del segnale (doppio conteggio trovato dai test). C1: nuovo `brain/cells.py` — `CellSpec` con knowledge scoping (USABILI/VISIBILI/RIPORTABILI), 10 ruoli, `Cell`, `EgressPermit`, `CellTeam`; cap del team = MINIMO sulle classi di contatto presenti (bug reale trovato dai test: con max() un ruolo report senza contatto alzava il cap delle cellule recon); escalation con peer advisory per i ruoli che toccano il target e guardia peer-storm (secondo bug reale trovato dai test: i peer advisory non facevano crescere il contatore). La cellula recon può riportare `vuln_class`/`attack_path` e non vede né pianifica alcuna capability `exploit` (verificato sul registry reale). Test nuovi: `tests/test_reasoning_lenses.py` (30) + `tests/test_cells_egress.py` (30). Regressione: 1 test rotto dal wire (`_decisions` su agente costruito con `__new__`) → accesso difensivo + `_stealth_veto` no-op senza arbiter. Suite: 2532 verdi, 2 skipped, 12 subtest, 0 failure. Restano C2 (orchestratore che istanzia il roster), C3 (triage + `--oM`) e C4 (sostituzione per sotto-fasi).

- 2026-09-14 · C2, C3, C4 (roster nell'orchestratore, triage + `--oM`, migrazione graduale) · (commit dev) · C2: nuovo `brain/cell_runtime.py` (roster+permesso+bus+tribunale dal run), `brain/bus.py` (request/response fra cellule), `brain/tribunal.py` (arbitrato dei disaccordi), wire in `agent.py` con `_exec_with_permit`/`_second_opinion`/`_cell_strict_here`; il vecchio `_execute_capability` resta il fallback leniente. C3: `brain/triage.py` (confeziona il caso per l'evolution) + `evolution/proposal.py` + modalità `--oM` con budget separato (`proposal_*`) nel ledger di stato. C4: migrazione per GOAL con gate di copertura per classe; tre bug reali trovati dal gate — (1) ledger INERTE perché `_current_stage` è il goal e non uno stadio di chain, (2) `beacon_deploy`/`ssh_login` erano categorie senza ruolo proprietario (rifiutate proprio le capability che consegnano il beacon), (3) roster costruito sulla sola chain: nessun `post` per la chain network e `scan_tcp` rifiutato 11 volte su un target identity (misurato, non teorizzato). Fix: coverage = chain + goal del run, goal beacon-bound sempre con copertura recon, foothold/exploit con le categorie mancanti, invariante di registry sul possesso delle categorie. Nuovi test: `tests/test_cells_runtime.py`, `tests/test_stage_migration.py` (16), `tests/test_cell_loop_e2e.py` (4, contratto behaviour-preserving: stessa SEQUENZA di capability e stesso esito con loop stretto e leniente). Suite: 2608 verdi, 2 skipped, 0 failure.
- 2026-09-15 · E3, E4, E5 (edge-aware doctrine + trasporto beacon reale) · (commit dev) · E3: nuovo `brain/edge.py` — `detect()` (CNAME/IP range provider/header/PTR), `provider_for_*`, `EdgeVerdict`/`OriginCandidate`/`EdgeReport`, `origin_candidates()` (PTR, split-horizon, CT log, header di origine leakati) con provenance+confidence; fatti `EDGE_FACT`/`EDGE_THRESHOLD` nel wm e `kit.best_origin(wm)`. E4: `_edge_guard(cap)` in `agent.py` rifiuta con MOTIVO ogni capability a contatto con l'edge del provider finché non esiste un origin credibile; `_run_origin_discovery()` + capability `origin_discovery` (recon, in-process, exec_class dichiarata) con adapter/interpreter che scrivono `origin_candidate`/`origin_host`; doctrine/planner: edge rilevato -> discovery dell'origine prima di ogni azione TCP. E5: trasporto beacon — ladder di endpoint (`C2_HOSTS`, `seed_ladder`/`prefer_endpoint`/`on_failure`/`on_success`, failover_after, argv host che NON distrugge la ladder), postura proxy (Windows AUTOMATIC_PROXY + override `C2_PROXY`, niente NO_PROXY; POSIX tunnel CONNECT con `proxy_from_env`/`proxy_bypassed`; macOS CURLOPT_PROXY), pin indipendente da mTLS (`BEACON_PIN_ENFORCED`: il fingerprint del leaf È la decisione, quindi funziona contro il self-signed del C2 dove il vecchio callback rifiutava sempre e il pin non veniva mai raggiunto), risoluzione dual-stack (`dial_tcp` con getaddrinfo AF_UNSPEC e tutta la lista), loop di scrittura completo su SSL_write/send (il body parzialmente scritto rompeva l'HMAC), `_c2_literal` che SCARTA un endpoint malformato invece di escaparlo, plumbing da `compile_beacon(hosts=..., proxy=...)` + `get_c2_fallbacks()/get_c2_proxy()`. Harness C++ `test_transport.cpp` compilato e LANCIATO in WSL ("ladder, rotation, proxy parsing, no_proxy all behave"). Tre bug reali trovati dal gate: (1) la guardia era ipersensibile ai commenti (`assertNotIn` scattava sulla prosa che spiegava la rimozione) -> negative su sorgente con commenti rimossi; (2) stessa classe di bug in `cdp_pivot.h` (gethostbyname + h_addr_list[0] = IPv4-only, primo indirizzo soltanto) -> `cdp_connect()` con getaddrinfo AF_UNSPEC e invariante esteso a ogni sorgente del beacon; (3) `cdp_pivot.h` non compilava FUORI da Windows (`Sleep` senza shim POSIX) -> shim aggiunto e TU compilato su Linux. Test nuovi: `tests/test_edge_doctrine.py` + `tests/test_beacon_transport.py` (24). Verifica: 192 passed sui file toccati, harness C++ verde.
- 2026-09-15 · E5-bis (pin nel build ordinario + decisione di rebuild) · (commit dev) · Colmato il buco che rendeva il pin codice morto: `BEACON_SERVER_FINGERPRINT` era emesso solo con `PHANTOM_MTLS_REQUIRED=1`, quindi in ogni build HTTPS ordinario il beacon completava il handshake con QUALSIASI server (payload AE S-GCM sigillato, ma peer non autenticato). Ora `c2_crypto.server_cert_fingerprint(cert_path="")` calcola lo SHA-256 del DER con la sola stdlib (`ssl.PEM_cert_to_DER_cert`), cioè il valore esatto che confrontano `CryptHashCertificate` su Windows e `X509_digest` su OpenSSL; `network.beacon_pin()` lo risolve (`mtls_server.crt` prima quando mTLS è on, altrimenti `server.crt`) con kill-switch `PHANTOM_BEACON_PIN=0`/`c2.pin=0`; `write_beacon_c2_config(pin=...)` lo emette e scarta qualunque valore che non sia un digest di 64 hex (niente escape del literal, niente pin non verificabile); `beacon_auth.py` mette `#ifndef` attorno al proprio define per non combattere con c2_config.h. Secondo fix della sessione: la decisione di rebuild nei 3 chiamanti (`api/server.py`, `modules/payload.py`, `automation/agent.py`) confrontava l'**intero header generato** con quello su disco — dopo E5 sempre diverso, quindi recompilazione forzata ad ogni build e fast path di freschezza mai preso. Ora `beacon_config_endpoint(beacon_dir)` legge C2_HOST/C2_PORT e si ricompila solo se l'endpoint bruciato nel binario cambia. Igiene: `c2_config.h` è l'unico header generato TRACCIATO mentre contiene token payload + stager PS in base64 e dichiara "do not edit manually" (segnalato nel report, non toccato: rimuoverlo dall'indice è una decisione). Test: `tests/test_beacon_transport.py` da 24 a **31** (pin dal certificato, pin nel define, pin malformato scartato, kill-switch, decisione di rebuild); harness C++ ricompilato e LANCIATO anche in versione PINNED (`BEACON_SERVER_FINGERPRINT` definito, `BEACON_PIN_ENFORCED=1`) e `main.cpp` verificato in sintassi con il pin. Verifica: 116 passed su beacon/api/payload/pm + 14 su test_c2_tls.
