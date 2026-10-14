# Phantom — Chiusura dei rilievi dell'audit (13 ottobre 2026)

**Data:** 13 ottobre 2026
**Branch:** `dev`
**Oggetto:** cosa è stato **corretto** in risposta a [`Audit_2026-10-13.md`](Audit_2026-10-13.md) — con la prova, non con l'intenzione.
**Metodo:** ogni rilievo è ricondotto a (a) il file che lo implementava male, (b) la correzione, (c) **il test che fallisce senza la correzione**. Le misure sono in fondo, ripetibili da riga di comando.

> **Relazione con gli altri documenti.** [`Audit_2026-10-13.md`](Audit_2026-10-13.md) è il **prima** (misurato su `b8a79eab`, tree pulito) e resta la fonte dei rilievi e delle evidenze originali. Questo documento è il **dopo**: la stessa lista, con lo stato attuale. Dove i due divergono, vale questo. La tabella di voto finale (§4) sostituisce quella di `Audit_2026-10-13.md §8.3`.

Un chiarimento di onestà che vale per tutto il documento: **una correzione vale quanto il test che la tiene**. Dove ho potuto, la prova è un test che fallisce se si ripristina il difetto; dove la prova è solo statica (una scelta di CI, un file di lock), è scritto.

---

## 1. Rilievo → correzione → prova

### P0 — la verità del risultato AutoMode

Il difetto era il più grave dei non-P0-e-basta: `AutoJob.state == "completed"` significava *il processo è tornato*, e nient'altro. Un run che non ha deployato nulla, non ha raggiunto nessun goal ed è stato rifiutato su ogni mossa leggeva **identico** a un run che ha percorso la kill chain.

| | |
|---|---|
| **Correzione** | Secondo asse accanto al lifecycle: `phantom/automation/engagement_outcome.py` — vocabolario degli esiti (`not_started`, `blocked_preflight`, `partial`, `completed_goal`, `completed_without_goal`, `failed_capability`, `awaiting_operator`), **derivazione conservativa** (`completed_goal` emesso *solo* se il run lo afferma), aggregazione per engagement e **preflight fail-closed** (`CALLBACK_GOALS`): un goal che richiede un callback viene **rifiutato prima di deployare** se `_ensure_c2_listener()` non ha un listener. L'esito attraversa `phantom/api/server.py` (API/UI), `phantom/core/automode.py` e `phantom/core/shell/commands/auto.py` (CLI). |
| **Prova** | `tests/test_engagement_outcome.py` — vocabolario, derivazione, aggregazione, e il preflight che rifiuta *prima* del deploy. |

Il difetto collaterale trovato nella Parte 0 §5.3 dell'audit (`_ensure_c2_listener()` il cui booleano era ignorato) è chiuso dallo stesso preflight: oggi il ritorno `False` **ferma** il run invece di aprire un engagement verso un check-in impossibile.

### P1 — report alla fine di OGNI fase (requisito 4)

L'audit lo dava per **non implementato** (voto 4/10). La verifica del codice lo ha smentito: il cablaggio esisteva già ed era la **scala a fine run** — cioè il requisito era centrato diversamente da come l'audit credeva.

| | |
|---|---|
| **Correzione** | `AutonomousAgent` accetta uno `stage_hook` e lo invoca alla fine di **ogni** stage (`_notify_stage`, `agent.py:3820`), sia nella scala multi-stadio sia nel run mono-stadio (`_notify_stage(goal, 1, 1, …)`, `agent.py:3405`); l'orchestratore lo collega a `phantom/core/automode_report.write_phase_report` (`automode.py:243,291`), che scrive un artefatto per fase. Un hook che solleva non abortisce uno stage finito: diventa una degradazione. |
| **Prova** | `tests/test_phase_reports.py` — l'artefatto per stage, l'ordine, il legame "stage soddisfatto ↔ esito riportato", e il fallimento di una fase che è **rumoroso ma non fatale**. |

### P1 — release Electron riproducibile

`electron/package-lock.json` era in `.gitignore` mentre la release workflow eseguiva `npm ci`: su un clone pulito la release **falliva prima di installare**, e la CI ordinaria non se ne accorgeva perché usa `npm install`.

| | |
|---|---|
| **Correzione** | Il lockfile è **committato** e la riga di `.gitignore:273` è sostituita dalla motivazione (`# electron/package-lock.json is COMMITTED ON PURPOSE…`); `electron-release.yml` allinea `npm ci` / `cache-dependency-path` al lock presente. |
| **Prova** | `tests/test_electron_release_lock.py` — il lock esiste, **non è ignorato**, e ogni workflow che esegue `npm ci` ha un lock contro cui eseguirlo. |

### P1 — un solo set di dipendenze Python, pinnato

`setup.py` dichiarava 11 dipendenze runtime, `requirements.txt` ne dichiarava 13: `pip install .` e `pip install -r requirements.txt` producevano ambienti diversi, e `.gitlab-ci.yml` installava dal manifest divergente — errore `fixture 'mocker' not found`.

| | |
|---|---|
| **Correzione** | `setup.py` **deriva** la lista da `requirements.txt` (una sola fonte); `constraints.txt` (nuovo) pinna il set verificato; `.gitlab-ci.yml` allineato a `ci.yml` invece di installare un sottoinsieme a mano. |
| **Prova** | `tests/test_dependency_manifests.py` — setup.py deriva, ogni dipendenza dichiarata è pinnata in `constraints.txt`, nessuna workflow installa dal manifest di packaging. |

### P1 — ogni errore catturato ha un NOME

Il problema non erano i 2365 `except Exception`: era che "eccezione catturata" non aveva una **tassonomia tipizzata**, quindi `tool_missing`, `out_of_scope`, `network_timeout` e `internal_bug` erano indistinguibili dall'esterno.

| | |
|---|---|
| **Correzione** | `phantom/utils/failure_taxonomy.py` — una categoria per ogni errore catturato, registrata in modo **osservabile** (decision audit + log) e restituita al chiamante; `record()` è totale, non può a sua volta sollevare. I **fail-open** elencati dall'audit sono chiusi: `broker._scope_ok` (non concede più lo scope perché una eccezione l'ha impedito di decidere), `ops.py`, `base.py`. La degradazione dell'agente porta la categoria (`agent.py:4036-4044`): l'evento `degraded` non dice più solo *quale* layer è morto ma *di che tipo* è il guasto. |
| **Prova** | `tests/test_failure_taxonomy.py`, più `tests/test_belief_revision.py::TestAgentWiring` (la degradazione porta la categoria) e `tests/test_execution_broker.py` / `tests/test_automation_agent.py` per il fail-open. |

### P1 — il manifest del driver è una *dichiarazione*, non una garanzia

`_binary_matches` fermava il manifest che nomina `nmap` ed esegue `curl`; non fermava la **sostituzione** — il nome risolve, il processo eseguito è un altro.

| | |
|---|---|
| **Correzione** | Il manifest può **pinnare** l'hash del binario (`binary_sha256`, `drivers.py:98`), validato in `manifest.py:121`; il broker verifica il pin **prima** di eseguire e rifiuta con un evento **nominato** (`driver_contract_violation`, `runtime/driver_contract.py:39`), non con un generico "tool unavailable". |
| **Prova** | `tests/test_driver_contract.py` — pin rispettato, sostituzione rifiutata con l'evento nominato, timeout dichiarato che prevale su uno spurio. |

### P1 — la matrice feature × OS × arch × transport

Prima: la CI provava che un binario **esisteva** per piattaforma, non **quali capability** quel binario portava. Una feature poteva diventare `windows_only` in silenzio e ogni job restava verde.

| | |
|---|---|
| **Correzione** | `phantom/utils/beacon_matrix.py` — la griglia come **dato** (feature con i verbi che dispatcha, l'header che le implementa, un livello di supporto per OS; più assi `ARCHES`/`TRANSPORTS`/`PINS`), con le regole che la leggono; `docs/beacon_platform_matrix.md` è ora verificato *contro il payload* e `scripts/beacon_matrix_verify.py` gira nella CI per ogni piattaforma (linux/windows/macos/android). |
| **Prova** | `tests/test_beacon_matrix.py` — ogni verbo appartiene a una sola riga; ogni file sotto `payloads/beacon/src` è classificato (un header nuovo non può essere aggiunto in silenzio); una feature dichiarata usabile su POSIX deve avere un ramo non-Windows; una `windows_only` deve **non** averne. |

### P1 — il benchmark AutoMode

L'audit: *"gira senza LLM e ha resume/supervisor/checkpoint con budget — ma la misura manca"*. Migliaia di test provavano che niente crashava, **non** che un run raggiungesse qualcosa.

| | |
|---|---|
| **Correzione** | `phantom/automation/benchmark.py` + `scripts/automode_benchmark.py`: **ground truth dichiarata** (ciò che il target esegue davvero), **failure injection** (`failures={"nmap": 2}`), metriche che non possono adulare (`goal_success`, falsi positivi = finding fuori dalla verità dichiarata, azioni inappropriate, *time to recover* dalla failure iniettata, sforamento di budget, interventi dell'operatore) e un esito **disallineato dal run segnalato come disonesto**. `docs/AutoModeBenchmark.md` è il come-si-legge. In CI il passo è **gating** (job `offline-sims`): uno scenario che rompe le proprie attese fallisce il job. |
| **Prova** | `tests/test_automode_benchmark.py` — i numeri vengono dal modello di esito di produzione e dallo stream dell'agente; la suite standard rispetta le proprie attese, offline. |

### P1/P2 — il data plane Go non è più un C2 più permissivo

`c2d` parlava lo stesso protocollo ma non applicava **nessuna** task policy, nessuna retention, nessun audit incatenato: cambiare backend **abbassava** silenziosamente le protezioni, e l'unica difesa era una riga di README.

| | |
|---|---|
| **Correzione** | `c2d/task_policy.go` (policy legacy/typed, cap di dimensione, expiry) e `c2d/audit.go` (catena `seq`/`prev`/`hash` verificata da `Verify()`), entrambe **pinnate alla controparte Python** da vettori condivisi: `c2d/policy_vectors.json` e `c2d/audit_vectors.json` (le attese sono quelle che ha prodotto **Python**). `docs/c2d.md` documenta scope e limiti; `/s/android` resta l'unica rotta non portata e risponde `501` con un corpo leggibile invece di un 404 silenzioso. |
| **Prova** | `tests/test_c2d_policy_parity.py` (la policy Python deve concordare con i vettori) + `cd c2d && go test ./...` (il lato Go asserisce gli stessi vettori) + `scripts/c2d_parity_check.py`, eseguito in CI. |

### P2 — il README non inventa flag (e non li nasconde)

| | |
|---|---|
| **Correzione** | `phantom/main.py`: le opzioni ignote **non sono più inghiottite** — `parse_known_args` resta (serve per i target extra di `--auto`) ma i token che iniziano con `-` vengono rifiutati con un messaggio che elenca ciò che il parser accetta (`main.py:147-157`). README corretto: `--no-stealth`/`--agent` rimossi (non esistono), entry point e conteggio test aggiornati, albero corretto, e **tutte** le flag del parser (32) documentate. |
| **Prova** | `tests/test_readme_contract.py` — ogni flag documentata esiste in `main.py`, **ogni flag del parser è documentata**, e i claim *contati* (file di test, rotte API) corrispondono al tree. Il conteggio non è più una cifra nella prosa che invecchia da sola: è un test che la ricalcola. |

### P2 — il `help` del core non può più nascondere un comando che esiste

`base.py` diceva "the 36 `do_*` commands" mentre ne erano registrati 46, e `malleable`/`guardrails`/`deps`/`llm` avevano **0** occorrenze nel file che rende `help`.

| | |
|---|---|
| **Correzione** | Il pannello è **verificato contro il registro** (`command_names()`) e ciò che le tabelle curate non coprono viene stampato dalle docstring degli handler: un comando nuovo non può restare invisibile. Le cifre nella prosa sono state rimosse, così non possono invecchiare. Il secondo motore kill-chain (`phantom/core/workflow.py`) non è più una superficie che *sembra* viva: il comando `workflow` mostra per ogni fase se un **esecutore è registrato** (`registered_phases()`, `system.py:1150`) e, quando il motore legacy non sa decidere, lo dice invece di tacere. |
| **Prova** | `tests/test_core_help.py`. |

### P2 — la rete di sicurezza dell'operatore

| Rilievo | Correzione | Prova |
|---|---|---|
| `--install-service` senza audit del ciclo di vita | `phantom/utils/service_units.py`: **voce di audit** per l'installazione (un file che parte al boot sopravvive al processo, quindi appartiene alla catena incatenata), **hash dell'invocazione** (file, messaggio e voce di audit sono confrontabili invece che creduti), **uninstall verificato**, e **rilevazione di una unit preesistente** — mai sovrascrivere in silenzio il file di un altro engagement. `--print-service` resta puro stdout. | `tests/test_service_unit_safety.py`, `tests/test_service_units.py` |
| `c2.auto_persist` ON di default, effetto laterale innescato da un check-in passivo | Il **default resta ON** (decisione del proprietario, Q-1) ma il consenso è **esplicito**: l'operatore può vedere la concessione *prima* che parta (`doctor`) e la traccia dell'engagement la dichiara nell'istante in cui il listener si apre, **con il modo esatto di revocarla**. | `tests/test_engagement_grants.py` |
| `install <tool>` esegue un package manager senza chiedere, `deps install` chiede | Una sola porta e una sola policy: entrambe usano `phantom.core.shell.ui.ask_to_install`, il prompt **nomina l'invocazione** del package manager, e una shell non interattiva (script/CI) non può innescarla per incidente. | `tests/test_install_consent.py` |
| Beacon deployato a mano senza nessuno che risponda (requisito 6 nel percorso manuale) | `exploit deploy-agent` e `payload deploy` usano lo **stesso** helper di auto-mode e lo stesso gate `c2.listener_auto_start`. Quando la porta è stata cambiata a mano (`session.lport` diverso), l'helper **non** viene chiamato — avviare un listener sulla porta sbagliata lascerebbe il beacon a comporre un numero morto — e l'operatore riceve il comando esatto. | `tests/test_manual_deploy_listener.py` |
| Crash-loop guard di `auto_resume`: `try/except: pass` sulla scrittura del contatore | Scrittura ancora best-effort (non deve uccidere un engagement che gira) ma **annunciata** dal notifier, con il numero di rilanci rimasti non contabilizzati. | `tests/test_resume_counter_guard.py` |

### P2 — Electron: accessibilità e schema sconosciuto

| Rilievo | Correzione | Prova |
|---|---|---|
| **zero** `aria-*` in tutto `electron/src` | Attributi e landmark (`role="status"`/`alert`, live regions, `aria-label`, focus visibile) sui punti in cui l'app parla da sola — status bar, stack dei toast, navigazione, canvas remoto. Nessun cambio di comportamento. | `tests/test_electron_a11y.py` (scansione delle sorgenti, stessa tecnica dell'allowlist IPC) |
| uno stato backend sconosciuto degradava in `idle` **in silenzio** | `asJobState` segnala il valore non riconosciuto (una volta per valore) invece di far dire al pannello che il motore è quieto mentre il contratto è rotto; il fallback resta sicuro. | `tests/test_electron_schema_mismatch.py` (compila `api.ts` con il tsc del progetto e guida `automodeStatus()` su un bridge IPC stub) |

### P2 — "installalo" senza clonare, e senza portarti dietro tutto

| Rilievo | Correzione | Prova |
|---|---|---|
| Docker build context = tutto il working tree (`COPY . .`, nessun `.dockerignore`) | `.dockerignore` (69 righe) | `tests/test_install_packaging.py` |
| L'installer copiava **l'intero** tarball (docs, test, Electron, `data/`) | Copia minimale per default, whole-tree come **opt-in esplicito**, branch richiesto onorato davvero, e l'archivio **verificato prima** di toccare il filesystem (una dimensione non dice cosa è arrivato) | `tests/test_install_packaging.py` |

---

## 2. Le due regressioni che la suite ha trovato (e come sono state chiuse)

La suite completa, dopo le correzioni, era **non verde**: 2 test rossi. Non li ho nascosti e non ho allentato le asserzioni.

1. **`test_belief_revision.py::test_hypothesis_resolution_failure_is_not_silent`** — rosso *perché* la correzione della tassonomia aggiunge `category` al payload dell'evento `degraded`: il test asseriva il dizionario **esatto** di prima. Il test è stato aggiornato per **pretendere la categoria** (`"category": "internal_bug"`): stesso intento (il fallimento non è silenzioso, layer e dettaglio corretti) più il nuovo contratto. Non è un allentamento: è un'asserzione in più.
2. **`test_readme_contract.py::test_the_test_file_count_matches_the_tree`** — `361 != 362`: i file di test aggiunti da questo lavoro non erano ancora nel conteggio del README. Il README è stato portato a **362**, e il test che lo verifica è esattamente il meccanismo che ha intercettato la staleness.

---

## 3. Misure (ripetibili)

```bash
# 1. la suite completa (parallela; seriale è il default del progetto)
python -m pytest -q -n auto
#   -> 2 failed, 5384 passed, 7 skipped, 108 subtests passed in 160.46s   (prima delle due correzioni §2)
#   -> vedi §5 per il run finale

# 2. i due file che erano rossi, dopo la correzione
python -m pytest -q -n auto tests/test_belief_revision.py tests/test_readme_contract.py
#   -> 31 passed in 3.33s

# 3. il renderer Electron (tsc del progetto)
cd electron && npx tsc --noEmit
#   -> exit 0, nessun errore

# 4. il data plane Go (i vettori di parità, dal lato Go)
cd c2d && go test -count=1 ./...
#   -> ok github.com/phantom/c2d 0.886s

# 5. sintassi degli installer
sh -n install/install.sh                    # -> exit 0
pwsh -NoProfile -Command '. { … Parser::ParseFile("install/install.ps1") … }'
#   -> PARSE OK (0 errors) — il parser PowerShell, non un `bash -n` travestito
```

Il conteggio dei file di test (362), delle rotte API e delle flag del parser **non è più una cifra da aggiornare a mano**: è calcolato da `tests/test_readme_contract.py` e fallisce quando diverge dal tree.

---

## 4. Giudizio aggiornato

| Area | Prima | Dopo | Cosa è cambiato |
|---|---:|---:|---|
| Ingegneria del repository | 7/10 | **8/10** | Lockfile committato, set di dipendenze unico e pinnato, installer e contesto Docker minimali, `.dockerignore` |
| CI e quality gates | 8/10 | **9/10** | La matrice beacon è verifica per-piattaforma, la parità `c2d` è un passo della CI, il benchmark AutoMode è **gating**, il job Docker costruisce davvero una stage, e i test che **eseguono** il renderer girano dove node esiste |
| C2/beacon — trasporto e task | 8/10 | 8/10 | — |
| C2/beacon — prova per-feature | 5/10 | **7/10** | Griglia feature × OS × arch × transport pinnata contro il payload e verificata in CI. **Resta**: la griglia classifica e verifica i rami, non **esegue** la feature su un OS reale |
| Core manuale | 7/10 | **9/10** | `help` impossibile da rendere incompleto, listener presente sui percorsi manuali, un solo consenso per il package manager, `workflow` esposto invece che morto |
| AutoMode lifecycle | 7/10 | 8/10 | — |
| AutoMode esito/reasoning | 5.5/10 | **8.5/10** | Secondo asse (esito ≠ lifecycle), preflight fail-closed **prima** del deploy, benchmark con ground truth, e il **supervisor** che usa l'esito per riprendere un run «finito» senza aver raggiunto nulla |
| Handoff beacon→C2 (req. 6) | 8.5/10 | **9.5/10** | Cablato **anche** nel percorso manuale; la porta sbagliata è un rifiuto dichiarato; la race sul check-in è chiusa da un **wait-to-appear** limitato |
| UI/Electron | 6.5/10 | **8/10** | Release riproducibile, a11y a contratto, stato sconosciuto segnalato, campi morti di `AutomodeStopResult` ora popolati, e i test del renderer **eseguiti** in CI invece che saltati |
| Deploy/deps | 6/10 | **8/10** | `constraints.txt`, manifest d'accordo, packaging minimale |
| Sessioni/.pm | 7/10 | **7.5/10** | `version` validata in lettura, `auto_export` non perde più un engagement con soli `results`/KB, e l'indice dei report nel bundle include i report **manuali** |
| Report per fase (req. 4) | 4/10 | **8.5/10** | Artefatto alla fine di ogni stage, mono-stadio compreso; il fallimento di una fase è rumoroso, non fatale. **Resta**: la verifica del contenuto per fase è su casi di test, non su un engagement lungo reale |
| Documentazione | 6.5/10 | **8/10** | README contract-tested, `c2d.md`/`service_units.md`/`AutoModeBenchmark.md` nuovi e indicizzati, indice che distingue canonico/storico |
| **Prontezza complessiva** | **6–6.5/10** | **8/10** | Il divario non è più "mancano la prova del risultato e la verità del report": il risultato ha un modello, una misura e un supervisore che agisce di conseguenza. Restano la prova **in esecuzione** per feature (beacon e BadUSB) e la verifica sotto carico reale |

### Cosa resta aperto (detto, non dimenticato)

1. **Esecuzione reale, non solo classificazione.** La griglia beacon prova *quali rami esistono* per piattaforma; nessuna feature è eseguita su un OS reale, e BadUSB non è mai stato flashato/digitato su hardware. È la distanza residua più grande tra "sembra fatto" e "è dimostrato".
2. **`c2d`**: `/s/android` resta Python (risponde `501`); la parità richiede che la CI abbia la toolchain Go — se non la ha, il passo va dichiarato **non eseguito**, non verde.
3. **`auto_persist`** resta ON di default: ora è visibile e revocabile, ma un effetto laterale innescato da un check-in passivo resta una scelta di default da rivedere con dati di campo.
4. **Benchmark**: è uno strumento con ground truth dichiarata dall'autore. Misura la coerenza del run con la realtà dichiarata, non sostituisce un engagement reale su un target ostile.
5. **Costanti storiche nei documenti datati** (3.319 / 3.710 / 3.881 / 166): restano dove sono e sono marcate come snapshot; l'unica cifra corrente è nel README radice, e ora è un test.
6. **Nessun `pyproject.toml`/`setup.cfg` e nessun config sample committato** (audit §5.6.5): **lasciato aperto di proposito**. `.env.example` già documenta che i settaggi vivono in `data/config.json` (auto-creato, gitignored) e che le env var sono override opzionali; un sample JSON committato sarebbe una **seconda** fonte di verità che nessuno confronta con i default reali.
7. **Nessuna immagine Docker pubblicata** (audit §5.5): resta "buildatela voi" — una decisione di distribuzione, non un difetto di codice. Il gate di CI ora costruisce davvero la stage `ci-smoke`, quindi il percorso Docker non è più non verificato.
8. **Nessun `.pm` d'esempio committato** (audit §6.5.6): un bundle è cifrato con una chiave locale all'operatore, quindi un sample committato sarebbe illeggibile senza spedire una chiave. Il round-trip resta validato dai test.

---

## 5. Run finale

Il run della suite completa, il typecheck del renderer, i test Go e la sintassi
degli installer sono la chiusura di questo documento.

```
python -m pytest -q -n auto -rs     -> 5414 passed, 8 skipped, 20 warnings, 108 subtests passed in 173.49s
                                      0 failed                          (albero finale)
cd electron && npx tsc --noEmit     -> EXIT=0, nessun errore
cd c2d && go test -count=1 ./...    -> ok github.com/phantom/c2d 1.152s  (GO_EXIT=0)
sh -n install/install.sh            -> exit 0
pwsh: Parser::ParseFile(install.ps1) -> PARSE OK (0 errors)

# il nuovo gate Docker, eseguito davvero su questa macchina (daemon 29.5.3)
docker run --rm -i hadolint/hadolint:2.12.0 \
    hadolint --failure-threshold error - < Dockerfile   -> exit 0 (solo warning di stile)
docker build --target ci-smoke -t phantom-ci-smoke .     -> BUILD_EXIT=0 (~1 min;
    pull della base + apt python3-pip + `pip install --dry-run -r requirements.txt`)
```

Questo run è stato eseguito **per ultimo**, sull'albero che contiene **tutte** le
correzioni — il primo passaggio (§1-§6) e il secondo (§7), `.gitignore` riparato
compreso — ed è il numero da citare. Rispetto ai `5386` del run precedente, i
`5414` includono i 28 test nuovi aggiunti dal secondo passaggio.

Gli 8 test saltati sono skip **dichiarati**, con la loro ragione, non test
disattivati da questo lavoro — ma non tutti gli skip sono uguali, e due
meritano di essere letti perché uno skip non prova niente:

| Skip | Ragione dichiarata |
|---|---|
| `test_audit_handovers.py:159` | `no PHASES export to compare against` — **l'asserzione non è mai eseguita** su questo albero: il test si auto-salta. Da sistemare. |
| `test_craft_netmap.py:387` | `no live hosts on this network` — dipendente dall'ambiente: compare solo se il segmento non risponde |
| `test_security_hardening.py:119` | `requires native nmap` (integration tool non installato qui) |
| `test_security_sweep_round2.py:49,60,107` | POSIX coreutils / nessun backend di esecuzione su questo host (Windows) |
| `test_smoke_generated_commands.py:97` | tool esterni non installati — e la ragione stampata è **illeggibile** (`: , bind, earchsploit, eploy, …`: i nomi dei tool vengono troncati) |
| `test_config_secret_perms.py:32` | bit di permesso POSIX (Windows usa una ACL) |

**Nota sulle flakiness.** Un run completo intermedio (lanciato per raccogliere
le ragioni degli skip) ha riportato `2 failed, 5384 passed`:
`test_viewer_send_queues_task` (`TimeoutError` su socket) e
`TestRecentlyExploitedCheck::test_cve_in_kev_is_flagged` (`PermissionError
[WinError 32]` — `rmtree` su `data/threatintel_cache/` mentre un altro processo
lo teneva aperto). Entrambi **passano in isolamento** (20 passed in 4.31s) e
nessuno dei due tocca il codice di questo lavoro: sono contesa sullo stato
condiviso in `data/` e timeout di socket, cioè debito di test da saldare
(isolare la cache per-worker), non regressioni del prodotto.

---

## 6. Igiene: la cache di stato del C2 non va committata

Trovato eseguendo la suite: `data/c2_state.json` compariva come file non
tracciato mentre i suoi fratelli erano già nell'elenco curato di `.gitignore`
(`data/c2_replay.json`, `data/c2_store.json`, `data/c2_audit.jsonl`). È stato
stato runtime — uno snapshot del data plane che nomina i target — quindi è stato
aggiunto all'elenco (`.gitignore:39`).

Da segnalare, perché è successo davvero: la **prima** scrittura di quella riga
ha rotto il file. `.gitignore` è in CRLF e lo strumento di edit ha unito due
righe in un commento (la regola `data/c2_replay.json` è sparita dentro la riga
di commento) e ha lasciato un CR spurio in coda a `data/c2_audit.jsonl`, che la
regola rendeva **inerte**. Se ne è accorti `git check-ignore`, non l'occhio:

```bash
git check-ignore -v data/c2_audit.jsonl data/c2_replay.json data/c2_state.json data/c2_store.json
#   -> tutte e quattro alla loro riga; prima della riparazione, due non rispondevano
python -m pytest -q tests/test_beacon_matrix.py tests/test_electron_release_lock.py \
    tests/test_state_store.py tests/test_ci_beacon_prepare.py tests/test_android_payload_assets.py \
    tests/test_payload_freshness.py tests/test_report_assets.py
#   -> 74 passed in 3.05s  (i test che leggono .gitignore)
```

Lezione che vale oltre questo file: un `.gitignore` modificato a mano va
**verificato con `git check-ignore`**, non riletto — una regola che non matcha
non produce alcun errore.

Dopo l'ultimo giro di test `git status --porcelain data` è **vuoto**: nessun
residuo di runtime non ignorato. Non servivano altre regole.

---

## 7. Secondo passaggio — ogni rilievo di `Audit_2026-10-13.md`, uno per uno

Il primo passaggio ha chiuso i P0/P1. Questo secondo passaggio ha **riletto
l'audit riga per riga** contro l'albero attuale, per rispondere a una domanda
diversa da quella del primo passaggio: non "cosa era importante?" ma "cosa era
scritto lì e non è ancora chiuso come si deve?". Ha trovato cinque voci
**parziali**, tutte chiuse qui (§7.2), e ha confermato con evidenza le altre.

### 7.1 Verifica puntuale

Legenda: **CHIUSO** = il difetto non esiste più ed è pinnato da un test; **CHIUSO
(decisione)** = non è un difetto da correggere ma una scelta motivata; **APERTO
(per natura)** = non chiudibile con codice in questo repo.

| Rilievo (audit) | Verdetto | Evidenza |
|---|---|---|
| §1.2.1 help incompleta + "36 `do_*`" | **CHIUSO** | `base.py` non dichiara più un numero (lo spiega nella docstring); il pannello è verificato contro `command_names()` con fallback dalle docstring → `tests/test_core_help.py` |
| §1.2.2 `workflow.py` superficie morta | **CHIUSO** | `cmd_workflow [show\|types\|next]` è registrato (`system.py:1085,1178`) e mostra per ogni fase se un esecutore è registrato (`registered_phases()`) |
| §1.2.3 listener C2 assente nel percorso manuale | **CHIUSO** | `exploit deploy-agent` e `payload deploy` usano l'helper e il gate di auto-mode → `tests/test_manual_deploy_listener.py` |
| §1.2.4 consenso incoerente per i package manager | **CHIUSO** | entrambe le porte passano da `ui.ask_to_install` → `tests/test_install_consent.py` |
| §1.3 fail-open `broker._scope_ok` | **CHIUSO** | ora `return False` + `record(...)` tipizzato (`broker.py:87-95`) |
| §1.3 swallow `ops.py:41`, `base.py:305`, `base.py:413` | **CHIUSO** | tutti e tre passano da `failure_taxonomy.record(best_effort=True)` |
| §2.4 doc stale che contraddice la CI | **CHIUSO** | `CROSS_PLATFORM_BUILD_STATUS.md` si apre con **SUPERSEDED** e nomina le due affermazioni false |
| §2.3/§2.4 'ogni feature verificata' / nessuna griglia | **APERTO (per natura)** | la griglia `feature × OS × arch × transport` esiste ed è pinnata contro il payload (`utils/beacon_matrix.py`, `tests/test_beacon_matrix.py`, `scripts/beacon_matrix_verify.py` in CI), ma **classifica**, non esegue: nessuna feature è eseguita su un OS reale |
| §2.5 BadUSB | **APERTO (per natura)** | generazione text-only; nulla viene flashato su hardware |
| §2.8.1/2 `c2d` senza policy/retention/audit/`/x` | **CHIUSO** | `c2d/task_policy.go`, `c2d/audit.go`, `MaxResultsPerBeacon`, `TaskLeaseSeconds`, `GET /x`; `policy_vectors.json`/`audit_vectors.json` pinnano Python↔Go |
| §2.8.3 `auto_persist` ON di default | **CHIUSO (decisione)** | il default resta ON (Q-1) ma la concessione è **visibile in `doctor`** e dichiarata nella traccia con il modo di revocarla → `tests/test_engagement_grants.py` |
| §2.8.4 `auto_shell` accoda un task al primo check-in | **CHIUSO** | è un **grant**, default **OFF**, auditato (`c2_server.py:79-95`) |
| §2.8.5 `docker-test` è un no-op che ingoia i fallimenti | **CHIUSO (§7.2)** | vedi sotto |
| §3.2 `--cell-loop` flag finto | **CHIUSO** | l'help dice "CELL LOOP (always on)… accepted for compatibility" (`main.py:55-59`) |
| §3.3 `completed` ≠ goal raggiunto | **CHIUSO** | `engagement_outcome.py` + preflight fail-closed → `tests/test_engagement_outcome.py` |
| §3.4 handoff: race sul check-in | **CHIUSO (§7.2)** | vedi sotto |
| §3.5 manca il benchmark | **CHIUSO** | `automation/benchmark.py` + `scripts/automode_benchmark.py`, passo **gating** in CI (`offline-sims`) |
| §3.6 `_write_counter` best-effort silenzioso | **CHIUSO** | annunciato dal notifier → `tests/test_resume_counter_guard.py` |
| §3.6 il supervisor non rilancia a fine pulita | **CHIUSO (§7.2)** | vedi sotto |
| §4.3.1 release non riproducibile | **CHIUSO** | lockfile committato; `ci.yml` ora installa con `npm ci` → `tests/test_electron_release_lock.py` |
| §4.3.2 `idle` silenzioso | **CHIUSO** | `asJobState` segnala il valore non riconosciuto → `tests/test_electron_schema_mismatch.py` |
| §4.3.3 campi morti di `AutomodeStopResult` | **CHIUSO** | `state`/`job` ora **parsati** (`api.ts:486-501`), pinnati da `test_the_stop_result_populates_the_fields_its_type_declares` |
| §4.3.4 i test che eseguono il renderer saltano in CI | **CHIUSO (§7.2)** | vedi sotto |
| §4.3.5 accessibilità zero | **CHIUSO** | `tests/test_electron_a11y.py` |
| §5.1 lock Python + manifest divergenti | **CHIUSO** | `constraints.txt`; `setup.py` deriva da `requirements.txt` → `tests/test_dependency_manifests.py` |
| §5.6.2 `.gitlab-ci.yml` divergente | **CHIUSO** | installa `-r requirements.txt -r requirements-dev.txt` e usa la **stessa** selezione di test di `ci.yml` |
| §5.6.3 installer su `main` + integrità solo dimensionale | **CHIUSO** | `PHANTOM_BRANCH` (default `dev`) + verifica della struttura dell'archivio e dei file attesi |
| §5.6.4 nessun `.dockerignore` | **CHIUSO** | `.dockerignore` (69 righe) → `tests/test_install_packaging.py` |
| §5.6.5 nessun `pyproject.toml`/sample config | **CHIUSO (decisione)** | motivato in "Cosa resta aperto", punto 6 |
| §5.5 nessuna immagine pubblicata | **APERTO** | scelta di distribuzione (punto 7) |
| §6.1/§6.5.2 `.pm` `version` non validata | **CHIUSO** | `check_version` su envelope **e** payload → `tests/test_session_bundle.py::TestVersionIsValidatedOnRead` |
| §6.5.4 `auto_export` scarta un engagement con soli `results` | **CHIUSO** | `session.results` conta come contenuto; il fallimento è rumoroso (`auto_session.py:169-206`) |
| §6.5.5 indice report solo `auto_*`/`agent_*` | **CHIUSO (§7.2)** | vedi sotto |
| §6.5.6 nessun `.pm` d'esempio | **APERTO** | vedi punto 8 |
| §7.2 README (flag inventate, conteggio, albero, entry point) | **CHIUSO** | `tests/test_readme_contract.py` |
| §7.3 flag nel codice ma non nel README | **CHIUSO** | lo stesso test confronta il parser con la documentazione |
| §7.4.3 `master_review.md` usato come fonte normativa | **CHIUSO** | l'indice lo classifica **"Reviewer INSTRUCTIONS, not findings"** |
| §7.4.5 sottosistemi senza pagina | **CHIUSO** | `docs/c2d.md`, `docs/service_units.md`, `docs/AutoModeBenchmark.md`, e la sezione Guardrails di `SECURITY.md` |
| §7.4.6 numeri di test incoerenti tra i documenti | **CHIUSO** | l'unica cifra corrente è nel README radice ed è **contract-tested**; i documenti datati sono marcati come snapshot |

### 7.2 Le cinque voci parziali chiuse in questo passaggio

1. **`docker-test` non era un gate.** Stampava "Dockerfile exists and checked"
eseguendo `alpine/shfmt` (che controlla gli script *shell*) con `2>/dev/null || true`:
un Dockerfile rotto passava verde. Ora il job fa due cose che possono fallire davvero
— `hadolint --failure-threshold error` e `docker build --target ci-smoke` — **e dice
cosa non costruisce** (l'immagine completa, con NDK e OpenSSL cross, è un job da 30+
minuti: quella la fa `docker compose build` e `gitlab-ci.yml::docker_build`). La
stage `ci-smoke` è nuova nel `Dockerfile`: pull della base, parsing, e
`requirements.txt` risolto **dentro** l'immagine. Pinnato da
`tests/test_install_packaging.py::TestTheDockerJobActuallyChecksSomething`.

2. **La race dell'handoff.** `run_c2(preferred_beacon=…)` risolveva l'id una volta
sola: se la registrazione atterrava un istante dopo si finiva nel ramo "beacon non
trovato" e l'operatore si ritrovava nel contesto **globale**, non sul beacon che il
run aveva appena stabilito. Ora passa da `_await_beacon_id`: attesa limitata (8 s,
poll a 4 Hz), poi il fallback con il tempo di attesa nel messaggio. `sleep`/`now`
sono iniettati, quindi il test non aspetta per davvero →
`tests/test_c2_handoff_wait.py` (7 test).

3. **Il supervisor si fermava su un run "finito" che non aveva ottenuto nulla.**
L'audit lo scriveva nella forma "*un engagement tecnicamente incompleto ma terminato
con exit 0 non viene rilanciato, e il supervisor non può sapere che il goal non è
stato raggiunto*": la seconda metà di quella frase non è più vera dal P0, perché il
run **restituisce** il proprio esito. `supervise(..., outcome_of=…)` ora tratta
`completed_without_goal`, `partial`, `blocked_preflight`, `failed_*` come lavoro
**non finito** e rilancia dallo stesso checkpoint **attraverso la stessa policy e lo
stesso budget** — che non viene azzerato, quindi non può diventare un loop. Un goal
raggiunto, `cancelled`/`awaiting_operator`, un token sconosciuto o l'assenza del
reader lasciano il comportamento di prima (nessuna sorpresa per i chiamanti
esistenti). `main.py` passa il reader; 11 test nuovi in `tests/test_auto_supervisor.py`.

4. **I test che ESEGUONO il renderer saltavano ovunque.**
`test_electron_job_state.py` e `test_electron_schema_mismatch.py` compilano `api.ts`
col `tsc` del progetto e lo guidano sotto node, ma fanno `skipif` senza
`electron/node_modules` — cioè in **ogni** job Python. Il job `electron-build`, che
`npm ci` lo esegue già, ora lancia anche quei due file: il predicato diventa una
verifica invece di uno skip. Pinnato in `tests/test_electron_release_lock.py`
(incluso il fatto che i due file **mantengano** la guardia di skip: toglierla
romperebbe la suite di chi non ha node).

5. **Il bundle `.pm` non nominava i report manuali.** L'indice percorreva solo
`data/sessions/auto_*` e `agent_*`, quindi un engagement i cui report venivano dal
generatore **manuale** (`report`, `export all` → `data/reports/report_*`,
`engagement_*`) viaggiava con un indice **vuoto**: proprio gli artefatti che
l'operatore consegna più spesso. Ora entrambi gli alberi sono indicizzati e le voci
manuali sono etichettate `reports/…` per non confonderle con le directory di run →
5 test in `tests/test_session_bundle.py`.

### 7.3 Cosa NON è stato toccato, e perché

* **L'esecuzione reale delle feature del beacon e del BadUSB.** Richiede VM Windows/Linux/macOS/Android e hardware HID. La griglia e il contract test dicono *cosa dovrebbe funzionare dove*; nessuno dei due può dire *che funziona*. È l'unico divario che questo repository non può chiudere da solo.
* **L'immagine Docker pubblicata**, il `pyproject.toml`, il config sample e il `.pm` d'esempio: scelte di distribuzione/igiene, motivate in §4. Nessuna delle quattro è una promessa non mantenuta: nessun documento le dichiara già fatte.

---

## 8. I file nuovi (creati da questo lavoro)

Nessuno di questi esisteva su `b8a79eab`. Sono elencati con la ragione per cui
esistono — se un file non ha una ragione in una riga, è un file di troppo.

### Moduli di produzione

| File | Cosa è, e quale rilievo chiude |
|---|---|
| `phantom/automation/engagement_outcome.py` | Il **secondo asse** accanto al job lifecycle: vocabolario degli esiti, derivazione conservativa, aggregazione per engagement, `CALLBACK_GOALS`. Chiude il P0 (§3.3 dell'audit: `completed` ≠ goal raggiunto). Puro, senza I/O. |
| `phantom/utils/failure_taxonomy.py` | Dà un **nome** a ogni errore catturato (`tool_missing`, `out_of_scope`, `internal_bug`, …) e lo registra in modo osservabile. Chiude il P1 "failure taxonomy" e i fail-open che l'audit aveva elencato. |
| `phantom/automation/runtime/driver_contract.py` | Verifica il **pin sha256 del binario** di un driver manifest (`driver_contract_violation` come esito nominato). Chiude §5.6: il digest era l'hash del *manifest*. |
| `phantom/utils/beacon_matrix.py` | La griglia `feature × OS × arch × transport` come **dato**, più le regole che la leggono. Chiude §2.3/§2.4 (lacuna n.1 del sottosistema). |
| `phantom/automation/benchmark.py` | Il benchmark AutoMode: ground truth dichiarata, failure injection, metriche che non possono adulare. Chiude §3.5 ("la misura manca"). |
| `c2d/task_policy.go` | La task policy (legacy + typed) sul data plane Go, pinnata alla controparte Python dai vettori condivisi. |
| `c2d/audit.go` | L'audit **incatenato** (`seq`/`prev`/`hash` + `Verify()`) al posto del JSONL modificabile senza traccia. |
| `c2d/policy_vectors.json`, `c2d/audit_vectors.json` | I **contratti condivisi** Python↔Go: le attese sono quelle che ha prodotto Python, e i due lati le asseriscono (Go in `task_policy_test.go`/`audit_test.go`, Python in `tests/test_c2d_policy_parity.py`). Senza questi file la parità sarebbe una promessa nel README. |
| `c2d/task_policy_test.go`, `c2d/audit_test.go` | Il lato Go della parità. |

### Test (ognuno è la prova di una correzione, non un test in più)

| File | Cosa pinna |
|---|---|
| `tests/test_engagement_outcome.py` | P0: vocabolario, derivazione conservativa, aggregazione, preflight fail-closed |
| `tests/test_phase_reports.py` | Requisito 4: un artefatto per **ogni** fase, mono-stadio compreso |
| `tests/test_c2d_policy_parity.py` | La parità Python↔Go dei due vettori |
| `tests/test_core_help.py` | Il pannello `help` contro il registro + `workflow` che mostra gli esecutori registrati |
| `tests/test_dependency_manifests.py` | `setup.py` deriva da `requirements.txt`; tutto pinnato in `constraints.txt` |
| `tests/test_driver_contract.py` | Il pin del binario e il rifiuto nominato |
| `tests/test_beacon_matrix.py` | Griglia contro il payload: ogni verbo, ogni header, ogni ramo POSIX/Windows |
| `tests/test_automode_benchmark.py` | La misura non può adulare: numeri dal modello di produzione, falsi positivi contati |
| `tests/test_electron_a11y.py` | Landmark, live region, `aria-label`, focus visibile |
| `tests/test_electron_release_lock.py` | Lockfile presente/non ignorato/coerente **e** il job che esegue i test del renderer |
| `tests/test_electron_schema_mismatch.py` | Stato sconosciuto segnalato (una volta per valore) + `AutomodeStopResult` che popola i campi dichiarati |
| `tests/test_engagement_grants.py` | `auto_persist` visibile in `doctor`, dichiarato nella traccia, revocabile |
| `tests/test_install_consent.py` | `install <tool>` chiede, come `deps install` |
| `tests/test_install_packaging.py` | `.dockerignore`, installer (branch, integrità, copia minimale), **e** il job Docker come gate reale |
| `tests/test_manual_deploy_listener.py` | Listener presente sui percorsi manuali (requisito 6), porta sbagliata = rifiuto dichiarato |
| `tests/test_readme_contract.py` | README ↔ `main.py`: flag documentate, flag esistente, conteggi ricalcolati |
| `tests/test_resume_counter_guard.py` | Il contatore anti-crash-loop che non sparisce in silenzio |
| `tests/test_service_unit_safety.py` | Service unit: audit, hash dell'invocazione, uninstall verificato, unit preesistente |
| `tests/test_c2_handoff_wait.py` | Il wait-to-appear dell'handoff (§7.2.2) |

### Documentazione e configurazione

| File | Cosa è |
|---|---|
| `docs/Audit_2026-10-13.md` | L'audit **prima** (misurato su `b8a79eab`, tree pulito): rilievi, evidenze, priorità. |
| `docs/Audit_Fixes_2026-10-13.md` | Questo documento: il **dopo**, con la verifica punto-per-punto e la tabella dei voti. |
| `docs/c2d.md` | Il data plane Go: cosa porta, cosa resta in Python (risposto `501`), come si esegue. |
| `docs/service_units.md` | `--print-service`/`--install-service`/`--uninstall-service`: cosa viene scritto, auditato e verificato. |
| `docs/AutoModeBenchmark.md` | Come si **misura** l'auto-mode, e cosa i numeri non provano. |
| `constraints.txt` | Il set di versioni **verificato**, opt-in: `requirements.txt` tiene i floor, questo file toglie il non-determinismo senza bloccare le patch di sicurezza. |
| `.dockerignore` | Il contesto Docker smette di essere l'intero working tree. |
| `electron/package-lock.json` | Il lockfile che la release chiede (`npm ci`) e che `.gitignore` teneva fuori dal repository. |
| `scripts/automode_benchmark.py`, `scripts/beacon_matrix_verify.py` | I due eseguibili che la CI chiama (benchmark **gating**, verifica della griglia per piattaforma). |
| `.gitignore:39` (`data/c2_state.json`) | Una riga in un file esistente: lo snapshot di stato del C2 non va committato (vedi §6). |
