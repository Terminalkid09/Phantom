# Phantom `dev` — Audit comparativo professionale
## Branch aggiornato al 5 ottobre 2026

> **Uso del documento:** review statica e di test del progetto Phantom in contesto di laboratorio/red-team autorizzato. Non è stata eseguita alcuna operazione contro target esterni, né è stato avviato il beacon/C2 su sistemi reali.

## 1. Executive summary

Il branch è cresciuto molto rispetto all’audit precedente: il diff dalla baseline `f6771f5` al commit `b751fe6` contiene **364 file modificati, circa 59.498 righe aggiunte e 5.613 rimosse**. Le aree nuove o significativamente ampliate comprendono:

- external intelligence e phone/geolocation intelligence;
- runtime tool drivers dichiarativi;
- swarm multi-agent e shared board;
- identity/OSINT graph, reasoning e success-rate accounting;
- remote session/viewer con input interattivo;
- hardening di C2, scope, TLS/mTLS, sessioni e Electron;
- una suite di test molto più ampia.

**Giudizio sintetico:** Phantom non è più un semplice prototipo da “target anni 2000”. È una piattaforma tecnica avanzata, con buone idee architetturali e una base di test insolitamente ampia. Tuttavia non la definirei ancora **enterprise-ready** senza una fase di hardening ulteriore: alcuni controlli dichiarati non sono applicati sul percorso reale, esistono confini di isolamento incompleti e alcune feature sono ancora adapter/marker o dipendono dall’ambiente locale.

### Priorità immediate

1. **P1 — Token API ruotato non aggiornato nel C2 server già importato.** La rotazione persiste un nuovo segreto ma `c2_server.API_TOKEN` resta quello precedente fino al restart del processo.
2. **P1 — Isolamento incompleto del remote viewer.** Un viewer autenticato per un beacon può ottenere l’elenco e il contenuto dei frame presenti nella directory condivisa `data/remote/`, senza filtro per beacon.
3. **P1 — Remote input Electron invia testo cumulativo a ogni tasto.** Digitando `abc`, il target può ricevere `a`, `ab`, `abc` e poi `abc` su Enter.
4. **P1/P2 — Driver runtime dichiarativi eseguiti come shell command.** La configurazione viene trattata come trusted, ma non esistono firma, approvazione, allowlist di binari o policy di provenienza; ciò è rischioso soprattutto con evolution/auto-learning.
5. **P2 — Auth matrix documentata ma non enforcement middleware.** `matrix_allows()` è una funzione di test/utility; `_setup_app()` registra solo `mtls_auth_middleware` e `api_auth_middleware`, quindi la matrice non è il punto di decisione centrale descritto dai commenti.
6. **P2 — API key esterne persistite in `data/config.json` in chiaro.** Il file è locale e la scrittura atomica è positiva, ma manca un secret store/OS keychain e una policy esplicita di permessi/verifica.
7. **P2 — Test ambientale non riproducibile.** La suite mirata ha avuto 202 passaggi e un fallimento perché il test presume `nmap` installato; la suite deve distinguere test di prodotto da prerequisiti locali.

## 2. Metodo e limiti

### Repository esaminato

- Repository: `Terminalkid09/Phantom`
- Branch: `dev`
- HEAD: `b751fe6c45aa61461fac326c9b33d00b63c379c8`
- Baseline di confronto: `f6771f55967e4d0d33c5c3536316736946dbaea3`
- HEAD subject: `docs(roadmap): log the phone/geolocation intel and the runtime tool drivers`

### Verifiche eseguite

- inventario e diff Git dalla precedente baseline;
- lettura statica di C2, API locale, Electron/preload, remote viewer, swarm/board, belief model, external/phone intel e runtime drivers;
- controllo pattern di subprocess, shell, token, auth, file write, import dinamici e route;
- raccolta pytest: **3.908 test raccolti**;
- suite mirata: **202 passed, 1 failed**;
- riproduzione isolata di due comportamenti con piccoli harness locali:
  - il board mantiene il primo finding anche quando arriva un secondo finding con confidenza superiore;
  - la rotazione API cambia il segreto persistito ma non `c2_server.API_TOKEN` già caricato.

Non sono state fatte scansioni, consegne, phishing, social engineering, accessi o deployment verso target reali. La review valuta implementazione e garanzie del codice, non può certificare invisibilità del beacon o successo operativo da un test personale.

## 3. Findings dettagliati

### F-01 — Token API ruotato: stato persistito e stato runtime divergono

**Severità:** P1 — alta

**Evidenza:**

- `phantom/core/c2_server.py:882-884` carica `API_TOKEN = get_api_token()` una sola volta all’import del modulo.
- `phantom/utils/c2_crypto.py:129-131` implementa `regenerate_api_token()` chiamando `regenerate_secret(...)`, ma non aggiorna il simbolo globale del C2 server.
- `phantom/api/server.py:387-394` espone la rotazione e restituisce il nuovo token.
- `phantom/api/server.py:3240-3250`, invece, legge dinamicamente `get_api_token()` per l’API locale.

**Riproduzione locale:**

```text
api_token_changed True
module_constant_is_new False
```

**Impatto:** dopo una rotazione, i client che usano gli endpoint REST del C2 possono fallire con il nuovo token mentre un percorso che usa il token vecchio può continuare a essere accettato fino al restart. Questo produce comportamento incoerente, revoca apparente ma non effettiva e troubleshooting difficile.

**Remediation:** eliminare il globale mutabile e leggere il token tramite un provider runtime; oppure implementare una funzione `reload_api_credentials()` che aggiorni atomicamente tutti i componenti e testare: old token rejected, new token accepted, in-process, senza restart.

---

### F-02 — Remote viewer non filtra gli artefatti per beacon

**Severità:** P1 — alta, riservatezza/integrità operatore

**Evidenza:**

- `phantom/core/remote_viewer.py:211-222` risolve un beacon e conserva `bid`.
- `phantom/core/remote_viewer.py:257-272` enumera semplicemente i primi file in `data/remote/` e li restituisce come frame “per questo beacon”.
- `phantom/core/remote_viewer.py:274-288` accetta qualsiasi `basename` esistente nella stessa directory e lo serve, senza verificare che appartenga a `bid`.

**Impatto:** il token del viewer è autenticato per la sessione di un beacon, ma il controllo di autorizzazione non copre il vincolo `viewer_session -> beacon_id -> artifact`. Un operatore con accesso a un viewer può vedere frame di altre sessioni locali. È una fuga di dati tra engagement/beacon, anche se il viewer è legato a loopback.

**Remediation:** introdurre un artifact store tipizzato con ownership esplicita; ogni frame deve avere `beacon_id` metadata e ogni route deve filtrare su quel valore. Non affidarsi a un prefisso filename: può collidere, essere troncato o essere alterato. Aggiungere test con due beacon e token separati.

---

### F-03 — Input testo Electron duplicato e stato UI ottimistico errato

**Severità:** P1 per correttezza della feature; P2 per sicurezza operativa

**Evidenza:** `electron/src/components/RemoteCanvas.tsx:140-148` invia a ogni keypress:

```text
sendInput('type ' + typeText + e.key)
```

ma aggiorna anche `typeText`. Con `abc`, l’input remoto può essere `a`, `ab`, `abc`; `onSendType()` alle righe 151-155 invia nuovamente il buffer su Enter. Inoltre `startStream()` considera sufficiente `res !== undefined` alla riga 53: una risposta HTTP 403/500 è comunque un oggetto definito e la UI può mostrare “streaming” nonostante il task non sia stato accettato.

**Impatto:** la remote session non è affidabile come controllo interattivo: digitazione duplicata, comandi involontari e stato visuale non allineato con il C2.

**Remediation:** scegliere un solo modello:

- input locale controllato e invio **una sola volta** su Enter; oppure
- key events individuali, senza buffer cumulativo e con mapping esplicito.

In entrambi i casi verificare `status` e payload prima di aggiornare `streaming/liveMode`; mostrare errori e rollback dello stato.

---

### F-04 — Runtime drivers: configurazione locale trasformata in shell execution senza trust policy

**Severità:** P1 nel percorso evolution/auto-learning; P2 nel solo uso manuale

**Evidenza:**

- `phantom/automation/runtime/drivers.py:118-190` accetta manifest JSON da directory packaged, `data/drivers`, `toolbelt.drivers_dir` e `PHANTOM_DRIVERS_DIR`.
- `phantom/automation/runtime/drivers.py:256-274` interpola il template con `str.format()` senza schema forte dei campi, quoting per tipo o validazione del binario.
- `phantom/automation/runtime/drivers.py:337-348` registra il driver come `exec_class="shell_command"`.
- `phantom/core/executor.py:668-737` esegue i command con `shell=True`.

Il codice documenta correttamente che i driver sono “operator-owned”, ma il loro ingresso nel planner automatico è più permissivo della superficie built-in. La validazione controlla categoria/forma del manifest, non la semantica del comando, la provenienza, la firma o l’allowlist dell’eseguibile.

**Impatto:** un driver non fidato, un file modificato dal processo evolution o una directory configurata accidentalmente possono introdurre esecuzione arbitraria locale e falsi finding. Il problema è soprattutto di supply chain e di separazione tra “knowledge learned” e “executable capability”.

**Remediation:**

- separare `discovered`, `approved` e `enabled`;
- firma/hash del manifest e approvazione esplicita per engagement;
- allowlist del primo binario e divieto di shell metacharacters salvo capability dichiarate;
- preferire `argv[]` a `shell=True` per driver normali;
- tipi slot (`host`, `port`, `url`, `path`) con quoting centralizzato;
- sandbox/lab per driver non approvati;
- loggare source path, hash, approver, timestamp e decisione policy.

---

### F-05 — Auth matrix dichiarata, ma non enforcement centrale

**Severità:** P2 — controllo di sicurezza incompleto

**Evidenza:**

- `phantom/core/c2_server.py:903-916` definisce `AUTH_MATRIX`.
- `matrix_allows()` alle righe 919-926 è descritto come usato dai test e da middleware futuri.
- `phantom/core/c2_server.py:1565-1567` installa solo `[mtls_auth_middleware, api_auth_middleware]`.
- `api_auth_middleware` alle righe 893-900 protegge tre path esatti; `mtls_auth_middleware` usa prefix per mTLS ma non applica la matrice route/principal/metodo.

**Impatto:** la policy dichiarata può divergere dalle route reali quando vengono aggiunti endpoint, alias, trailing slash, metodi o percorsi malleabili. Non ho attribuito automaticamente un bypass remoto a questo finding: le route individuali possono avere controlli propri. Il problema dimostrato è l’assenza di una singola enforcement point e la possibilità di regressione silenziosa.

**Remediation:** middleware unico che calcoli principal, normalizzi path e metodo, applichi deny-by-default alla matrice e deleghi poi all’handler la verifica HMAC specifica. Testare ogni route con matrix allow/deny, slash variants, method variants e principal mismatch.

---

### F-06 — API key esterne salvate in plaintext nel config plane

**Severità:** P2 — hardening host/operator

**Evidenza:**

- `phantom/utils/config.py:139-145` inserisce Shodan/NVD/GitHub sotto `api_keys`.
- `phantom/utils/config.py:225-253` salva il JSON localmente con scrittura atomica, ma non usa un OS keychain/secret manager e non verifica/normalizza i permessi del file già esistente.
- `electron/src/components/SettingsPanel.tsx:241-249` comunica che le key sono in `data/config.json`.

**Impatto:** backup, sincronizzazioni, malware locale, crash dump o condivisione accidentale della directory possono esporre credenziali riutilizzabili. La mascheratura in UI non protegge il file.

**Remediation:** keychain Windows Credential Manager/macOS Keychain/libsecret; fallback cifrato con chiave legata all’utente; `0600`/ACL verificati; redazione di config export e doctor; rotazione e test di non-leak nei log.

---

### F-07 — Scope opt-out test non riproducibile per dipendenza esterna

**Severità:** P2 — qualità CI/test

**Evidenza:** suite mirata:

```text
202 passed, 1 failed
TestScopeFailClosed.test_unscoped_opt_out_env
AssertionError: expected returncode != -1, got -1
```

Il test invoca `nmap -sV 10.0.0.5` e presume che `nmap` sia disponibile. Nell’ambiente di audit il fallimento è coerente con tool assente, non con un bypass dello scope.

**Impatto:** CI verde/rossa in funzione del workstation setup; rischio di mascherare regressioni reali e di rendere i risultati non confrontabili.

**Remediation:** mockare `backend_dispatcher`/executor per il test dello scope; aggiungere un test separato `requires_tool("nmap")`; marker pytest `integration_tool`; container CI documentato per i test reali.

## 4. Valutazione logica e architetturale

### 4.1 Belief model vs swarm board

`phantom/automation/belief.py:118-165` implementa una revisione corretta per confidenza: una nuova evidenza più forte sostituisce quella debole e registra una `Revision`. Il board swarm, invece, ha una semantica diversa e più rigida: il primo writer riserva la chiave. Questa differenza è pericolosa perché il planner può osservare risultati diversi a seconda dell’ordine di scheduling.

**Rischio:** un’osservazione external-intel a bassa confidenza può diventare il valore condiviso permanente del board, mentre un worker nmap/LDAP successivo non riesce a pubblicare il dato più forte. Il WorldModel individuale può correggere il dato, ma il coordinamento multi-agent resta stale.

**Miglioramento:** usare versioni monotone per finding, `confidence`, `evidence_quality`, `source_reliability` e merge CRDT-like; mantenere tutti i contributi e calcolare il best current belief. “First writer wins” va riservato a lock/idempotency, non alla verità del mondo.

### 4.2 Error handling e concorrenza

La crescita del numero di worker e capability è buona, ma la readiness enterprise richiede:

- idempotency key per task e result;
- lease con expiry per task assegnati;
- retry policy per categoria di errore, non solo timeout generico;
- deduplica tra swarm e AutoMode principale;
- causal ordering o vector clock per finding contraddittori;
- cancellation propagata a subprocess e figli;
- budget per target, non solo budget globale del run;
- checkpoint transazionale del board e del world model.

### 4.3 Esecuzione shell

La scelta di `shell=True` è funzionale alla CLI e alle pipeline, ma rende ogni nuovo adapter una possibile injection boundary. La validazione del target riduce il rischio più ovvio, non protegge automaticamente username, password, URL, port, path, marker template o valori provenienti da driver/plugin. La regola architetturale dovrebbe essere: shell solo per capability esplicitamente classificate `pipeline`, argv per tutto il resto.

## 5. Maturità delle feature rispetto a scenari enterprise

| Area | Stato attuale | Valutazione | Cosa manca per livello enterprise |
|---|---|---|---|
| C2/beacon | Wire protocol, HMAC, anti-replay, TLS/mTLS e fallback presenti | Forte base, ma non certificabile come enterprise per la rotazione token e policy distribuite | key lifecycle in-process, revocation verificabile, HA, audit immutabile, test cross-platform |
| Scope | CIDR/hostname/URL e fail-closed migliorati | Buono come safety gate | scope signed per engagement, DNS rebinding testato end-to-end, policy non bypassabile da plugin |
| AutoMode | Planner, hypotheses, reasoning, failure memory, noise accounting | Architetturalmente ambizioso e superiore a un semplice script | outcome calibration, deterministic replay, action approval tiers, per-target budgets, evidence quality |
| Swarm | Fan-out, board, workers, merge, failure handling | Buono per prototipo avanzato | merge per confidenza/versione, leases, backpressure, durable queue, worker isolation |
| External intel | Adapter API, fallback e confidence | Utile, ma dipendente da provider e rate limit | provider contracts, provenance, caching con TTL, quota/cost budgets, PII policy |
| Phone/geolocation intel | Parsing e capability di enrichment | Feature di supporto, non prova di identità o localizzazione reale | distinguere possible/valid, confidence calibration, provider provenance, minimizzazione PII |
| BloodHound/AD graph | Ingest e graph reasoning integrati nel core manuale | Valore reale se i dati sono raccolti correttamente | versioni schema BloodHound, import fixture enterprise, edge provenance, stale graph detection |
| Remote session | Frame stream, input mouse/keyboard, Electron viewer | Idea professionale e fattibile; implementazione ancora da correggere | isolamento artefatti, ACK task, input batching, resize/coordinate tests, backpressure, kill guarantee |
| OSINT/social/phishing | Planner/capability taxonomy, alcuni adapter e transport reali | Parte significativa è orchestration/marker e dipende da integrazioni esterne | provider adapters completi, consent/scope records, rate limits, evidence chain, test anti-false-positive |
| Runtime drivers | Estensibilità molto utile | Potente ma trust-sensitive | signed plugins, typed argv, approval workflow, sandbox e provenance |
| Electron | IPC/preload allowlist e CSP migliorati | Buona base | test E2E, error-state correctness, secure storage, session isolation |
| Learning/evolution | Experience, lab/gate, proposal/PR workflow | Buona direzione: preferibile alla modifica diretta di `dev` | separazione dati/codice, reproducible replay, review policy, signed artifacts, rollback e kill switch |

## 6. Cose che funzionano bene e vanno preservate

- **Fail-closed scope** e distinzione tra target unsafe, out-of-scope e tool unavailable.
- **Per-beacon crypto derivata** e anti-replay, più robusta del vecchio segreto globale.
- **WorldModel con revision history**, perché rende visibile la contraddizione invece di sovrascrivere silenziosamente.
- **Honest success-rate accounting**, che distingue reached, halted, cycled e degraded.
- **API locale loopback + bearer auth + CSP/CORS restrittivi**.
- **Separazione proposal/branch/PR nell’evolution**, molto più sicura dell’auto-modifica del branch di lavoro.
- **Test negative e di hardening**: la quantità e la varietà sono un punto di forza reale.
- **Remote session come modulo separato**: concettualmente è meglio di sovraccaricare il beacon base, purché il canale resti explicitamente autorizzato, scadibile e revocabile.

## 7. Piano di remediation prioritario

### P0 — prima di qualsiasi demo enterprise

1. Fix F-01: token provider runtime e test di rotation in-process.
2. Fix F-02: artifact ownership per beacon e test cross-session.
3. Fix F-03: input model singolo, status handling e test UI/E2E.
4. Aggiungere un `security invariant test suite` che avvii l’app e verifichi route reali, non solo funzioni helper.

### P1 — prima di abilitare evolution/driver automatici

1. Driver approval/signature/hash e allowlist executable.
2. Separazione tra learned knowledge, candidate capability e enabled executable.
3. Eliminazione di `shell=True` dai driver normali; argv typed.
4. Merge del board basato su evidenza/confidenza/versione.
5. Per-target budgets, task leases e cancellation end-to-end.

### P2 — qualità e enterprise operations

1. Secret store OS per API keys.
2. CI con unit, integration-tool e E2E separati.
3. Provider contracts e fixture offline per external/phone intel.
4. Provenance completa per ogni finding, inclusi provider, timestamp, TTL e trasformazioni.
5. Telemetria locale auditabile: chi ha abilitato capability, quale policy, quale scope, quale decisione.

## 8. Test aggiuntivi raccomandati

```text
- test_api_token_rotation_updates_c2_middleware_without_restart
- test_old_api_token_rejected_after_rotation
- test_remote_viewer_cannot_list_other_beacon_frames
- test_remote_viewer_cannot_fetch_other_beacon_frame_by_name
- test_remote_canvas_type_sends_once_on_enter
- test_remote_canvas_http_error_does_not_set_streaming
- test_driver_requires_approval_before_execution
- test_driver_slot_host_is_shell_quoted_or_argv_encoded
- test_driver_manifest_hash_is_logged_and_verified
- test_board_stronger_finding_supersedes_weaker_finding
- test_board_concurrent_conflicting_findings_are_deterministic
- test_unscoped_scope_test_uses_mock_tool_not_local_nmap
- test_config_export_redacts_api_keys
- test_api_key_storage_uses_keychain_or_encrypted_fallback
```

## 9. Verdetto finale

**Phantom è un progetto interessante e tecnicamente serio per la sua fase.** Le qualità più importanti non sono il numero di comandi, ma il tentativo di modellare scope, evidenza, confidenza, failure, opsec accounting, swarm e learning come concetti espliciti. Questo lo distingue da una raccolta di script.

La distanza rimanente dall’enterprise non è principalmente “aggiungere altri exploit” o rendere il beacon più aggressivo. È rendere **deterministici, verificabili e isolati** i confini già presenti: identità, token rotation, artifact ownership, driver trust, merge dei finding, cancellation, provenance e test runtime. Una volta sistemati questi punti, AutoMode può diventare molto più credibile come orchestratore autonomo professionale, perché saprà non solo scegliere mosse, ma anche dimostrare perché una decisione è autorizzata, quale evidenza la sostiene e come revocarla.

**Conclusione:** architettura promettente e sopra la media dei tool personali; non ancora pronta per essere dichiarata enterprise-grade senza il remediation plan P0/P1.


## 10. Risultato suite completa e triage dei failure

La suite completa è stata eseguita sul checkout aggiornato:

```text
3881 passed, 17 failed, 4 skipped, 6 errors, 12 subtests passed, 1 warning
3908 test raccolti
Durata: 688.38 s
```

Il risultato è buono come volume di comportamento coperto, ma non è un verde accettabile per una release enterprise. I failure non hanno tutti lo stesso significato.

### Failure da trattare come regressioni/issue di prodotto

- `tests/test_electron_allowlist_sync.py::test_every_ui_endpoint_is_allowlisted`
- `tests/test_endpoint_allowlist_drift.py::test_ui_endpoints_are_all_allowlisted`
- `tests/test_endpoint_allowlist_drift.py::test_every_ui_path_literal_is_reachable`

Questi tre failure indicano drift tra endpoint usati dalla UI, allowlist IPC/API e route realmente registrate. Vanno trattati come P1 di integrazione: una UI che chiama una route non consentita o non raggiungibile può fallire in modo silenzioso e, peggio, un endpoint raggiungibile ma non censito può sfuggire all’audit della superficie.

Sono inoltre da trattare come issue concrete della pipeline learned/evolution:

- `test_security_sweep_round2.py::test_descriptor_read_out_of_process`
- `test_security_sweep_round2.py::test_reconstructed_capability_carries_no_callables`
- `test_security_sweep_round2.py::test_worker_returns_findings_as_data`

Il descriptor restituisce `None` per il probe out-of-process; la ricostruzione successiva assume invece un dict e produce `AttributeError`. Questo rompe sia il contratto di introspection sia il percorso che dovrebbe impedire di importare callables non fidati. Il sistema deve fallire in modo typed e non proseguire con dati `None`.

Altri failure potenzialmente reali da verificare subito:

- `test_differential.py::test_http_probes_on_unreachable_host`: verificare il contratto tra errore di rete, finding e fallback; un unreachable host non deve essere confuso con un servizio assente o con un planner failure.
- `test_manual_core.py::test_export_full_set_writes_four_files`: verificare packaging/export degli artefatti e directory di destinazione.
- `test_manual_ux.py::test_run_quiet_executes_top_suggestion`: verificare che quiet mode non richieda input o stato globale residuo.
- i test Android (`test_mobile_chain.py`, `test_remote_android.py`): se Android è dichiarato supportato, la mancata presenza del source tree/config/service manifest è una lacuna di feature; se è opzionale, i test devono essere marcati con il prerequisito corretto.

### Failure probabilmente dipendenti dall’ambiente o dai prerequisiti

- `test_security_hardening.py::TestScopeFailClosed::test_unscoped_opt_out_env`: già osservato nella suite mirata; presume `nmap` installato. Va mockato o marcato come integration-tool.
- `test_toolbelt.py::test_os_adapter_consumes_chosen_tool`: il ramo `-O` dipende da raw socket/privilegi; il test dovrebbe iniettare la capability di raw socket invece di usare l’ambiente del runner.
- `test_execute_quiet.py::test_read_output`, `test_write_stdin`, `test_p1_typed_and_learning.py::test_execute_quiet_timeout_kills_tree`: verificare OS/process-group semantics nel runner; non vanno interpretati come pass se il test non è stabile su Linux/Windows supportati.
- i sei errori di `payload_engine_core` e `payload_freshness`: prima di classificarli come regressioni bisogna controllare dipendenze/toolchain e fixture di build. Se il requisito è che la suite unitaria sia offline, il code path deve usare un fake engine; se richiede compiler/toolchain, devono essere test integration marcati.

### Warning

È stato rilevato un `RuntimeWarning` per `C2Server.stop.<locals>.cleanup` non awaited durante un test di redaction. Anche se non ha causato il failure, segnala un possibile lifecycle bug nei test/server asincroni: cleanup e loop devono essere sempre awaited o chiusi esplicitamente.

### Azione raccomandata sul CI

Separare la pipeline in quattro job espliciti:

1. `unit-hermetic`: nessun binary esterno, nessuna rete, fixture/mocks obbligatori;
2. `integration-tools`: nmap, ffmpeg, compiler, adb/NDK e tool AD installati in container;
3. `electron-e2e`: build frontend, allowlist sync, route reachability e IPC;
4. `security-sweep`: descriptor/evolution/driver isolation, eseguiti su Linux e Windows supportati.

Il gate di merge deve richiedere verde per `unit-hermetic`, `electron-e2e` e `security-sweep`; i failure di `integration-tools` possono essere classificati separatamente, ma mai ignorati o mescolati ai test unitari.
