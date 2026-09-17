# Phantom `dev` — Professional Security & Architecture Audit

**Repository:** `Terminalkid09/Phantom`  
**Branch:** `dev`  
**Commit auditato:** `f6771f55967e4d0d33c5c3536316736946dbaea3`  
**Ultimo commit:** 12 settembre 2026, 21:52 UTC  
**Data audit:** 13 settembre 2026  
**Metodo:** analisi statica del repository aggiornato, lettura dei percorsi nuovi e modificati, raccolta di pattern di rischio, compilazione sintattica Python e raccolta della suite test. Non sono stati avviati beacon, C2, payload, exploit, phishing, social delivery, remote-control module o scansioni verso target.

## Executive summary

Il branch è cresciuto in modo sostanziale rispetto alla review precedente. Il checkout contiene **558 file tracciati**, di cui circa **308 nel package `phantom`**, **161 test**, una directory `lab`, un’app Electron e una nuova pipeline di **self-learning evolution**. Gli ultimi 18 commit aggiungono circa **231 file e 39.236 righe**, includendo AutoMode modulare, C2 con lease e audit, beacon cross-platform, remote session GUI, social engineering avanzato, exploit hunt, lab evolution e nuove integrazioni Electron.

Dal punto di vista ingegneristico, il progetto ha fatto progressi importanti. In particolare, sono presenti un gate a più stadi per capability generate, un sandbox di scrittura stretta per l’autore LLM, un laboratorio Docker dedicato, HMAC per beacon enrolled, task lease, deduplicazione dei risultati, hash-chain audit e test di hardening. Queste sono basi corrette per rendere il sistema più deterministico e verificabile.

Dal punto di vista del rischio, il prodotto non è più classificabile come una semplice CLI di assessment. Il branch contiene un **framework operativo multi-capability** con C2, persistenza, process injection, reflective loading, keylogging, camera/audio/GPS capture, screen recording, remote desktop, payload delivery, shellcode generation, RCE bridge, social delivery e moduli exploit. In una review enterprise questi componenti devono essere trattati come superfici separate, con capability manifest e autorizzazione tecnica per ogni operazione.

### Giudizio complessivo

| Area | Valutazione | Sintesi |
|---|---:|---|
| Architettura generale | C+ | Modularità notevole, ma troppi percorsi condividono stato, task e boundary di esecuzione |
| AutoMode | C+ | Reasoning e phase model migliorati; lifecycle e side effect richiedono ulteriore isolamento |
| Evolution engine | B- | Buon modello sandbox/gate/PR; promozione e import dinamico hanno rischi residui |
| C2/beacon | C | Lease e HMAC sono buoni; default behaviour e capability operative sono troppo potenti |
| Remote session | C- | Viewer funzionante come prototipo, ma il controllo è ancora un’iniezione di comandi in-band |
| Electron | C+ | UI ricca; IPC, polling e autenticazione locale devono essere più tipizzati |
| Test e CI | C | Molti test e buone intenzioni; suite non eseguibile nell’ambiente audit e coverage dei confini incompleta |
| Readiness operativa | **Non pronta** | Necessari hardening, test eseguibili, threat model e revisione delle capability ad alto impatto |

## Limitazioni e materiale non verificato

La suite Python non è stata eseguita perché nell’ambiente corrente manca `pytest`; `python3 -m pytest --collect-only` termina con `No module named pytest`. La compilazione sintattica con `python3 -m compileall -q phantom tests` è invece riuscita. Sono state osservate `SyntaxWarning` nei test per regex non raw, ma non errori di sintassi. Non sono stati compilati i binari C/C++/Android e non sono stati avviati Docker, C2, lab o viewer.

L’audit è quindi una **review statica aggiornata**, non una certificazione di sicurezza runtime. Le linee indicate sono riferimenti al checkout corrente e devono essere ricontrollate quando il branch cambia.

# 1. Inventario e cambiamenti recenti

Gli ultimi commit introducono, tra gli altri, i seguenti blocchi:

| Commit/area | Impatto architetturale |
|---|---|
| Modular AutoMode brain | Phase architecture, doctrine, operator/hypothesis ledgers |
| Auto-mode reasoning depth | Guidance kits, planner wiring, evidence-tagged suggestions |
| Self-learning evolution engine | Author LLM, sandbox, gate, lab, beta loading, branch/PR publishing |
| OSINT/social chain | Dossier, persona, phishing, DM, IP grabbers, video lures |
| Post-exploitation chain | Persistence, privilege escalation, lateral movement, AD, injection |
| C2 server/shell | Task leases, HMAC/mTLS support, audit, beacon lifecycle, artifact storage |
| Hardened beacon | Evasion, camera/GPS/audio, watchdog, injection and migration |
| Remote session | Windows/Linux/Android GUI capture and input |
| Exploit hunt | Anomaly engine, differential probes, PoC synchronization |
| Electron | C2 dashboard, remote canvas, recordings, learning panel, audit viewer |

La modularità è un punto di forza, ma la quantità di capability rende necessario un modello di autorizzazione **compositivo**. Un singolo `beacon connected` o un singolo token C2 non dovrebbe implicare accesso a tutte le capability.

# 2. Finding critici e high

## F-01 — API di esecuzione generica ancora ad alto impatto

**Severità:** Critical  
**Area:** local API, backend dispatcher, executor.  
**Rischio:** command execution arbitraria se un client locale, renderer compromesso o token API viene abusato.

La precedente criticità relativa a `module_run`/`backend_run` e al passaggio verso `execute_quiet` con `shell=True` resta una priorità finché gli endpoint non sono trasformati in capability typed e allowlisted. Le route devono accettare un `capability_id` e argomenti validati, non una stringa shell. Il server deve costruire argv internamente e applicare lo scope alla destinazione effettiva.

**Acceptance criteria:** nessun endpoint esposto al renderer accetta shell generica; `shell=False` dove possibile; test che provano injection, tool name non allowlisted, target non presente nel manifest e argomenti extra.

## F-02 — Credential/OTP capture e propagazione nel trail

**Severità:** Critical  
**Area:** social engine e tracker.  
**Evidenza aggiuntiva dell’analisi indipendente:** il trail può incorporare `password` e `otp` nel percorso degli eventi.

Il contesto autorizzato può richiedere una capability di assessment, ma l’implementazione attuale tratta dati di autenticazione come normali campi. Questo crea rischio di persistenza nei log, report, audit, risultati C2 e backup.

**Correzione:** mantenere eventuali capability di assessment solo sotto manifest firmato, destinatari pre-registrati e policy server-side, ma rendere password/OTP/cookie/token tipi non persistibili. La redazione deve avvenire prima dell’event bus e non soltanto in una view. Devono esistere test end-to-end che inseriscono valori canary e verificano che non compaiano in alcun output.

## F-03 — Payload delivery e remote deployment con percorsi nascosti

**Severità:** Critical  
**File:** `phantom/payloads/beacon/src/main.cpp`, circa 810–895; `phantom/core/c2_server.py`, circa 732–797; `tests/test_remote_module.py`.

Il beacon può scaricare il remote module usando token incorporato, scriverlo con nome nascosto e finestra nascosta su Windows, eseguirlo in-memory su POSIX o installare un APK con `pm install -g`. I test verificano intenzionalmente PowerShell hidden, `curl -sk`, `/tmp/.rdesk`, installazione APK e self-delete.

Questo è un comportamento ad alto impatto, indipendentemente dall’intento dichiarato. Il problema architetturale non è soltanto il token: mancano session manifest, capability grant distinto per screen/input, consenso locale o indicatore obbligatorio, scadenza della remote session e revoca verificata dal modulo.

**Correzione:** remote session come capability separata e signed task; view-only iniziale; interazione su seconda autorizzazione; indicator locale non occultabile nei profili ordinari; niente auto-install dal beacon con token globale; session expiry, revocation e audit end-to-end; file transfer e clipboard separati.

## F-04 — Persistenza automatica all’arrivo del beacon

**Severità:** Critical  
**File:** `phantom/core/c2_server.py`, circa 107–135; `phantom/core/c2_shell.py`, circa 731–751.

`update_beacon()` accoda automaticamente `persist` quando un beacon nuovo viene registrato. Questa è una scelta di default pericolosa perché l’evento di check-in produce un side effect di persistenza senza una decisione di engagement visibile nel codice esaminato.

**Correzione:** rimuovere l’auto-persist come default; richiedere un manifest con `persistence` esplicitamente consentita, una task approval e un target/host scope. Il comportamento iniziale deve essere `register-only` e la persistenza deve produrre un audit e un rollback receipt.

## F-05 — Capability di injection, migration, shellcode e reflective loading

**Severità:** Critical  
**Area:** `phantom/payloads/beacon/src/injection.h`, `evasion.h`, `reflective_loader*`, `c2_shell.py`.

Il repository include process injection, process hollowing, indirect syscalls, PPID spoofing, in-memory execution, shellcode generation e migration. Queste capability sono ad alto rischio e non devono essere rese disponibili dal solo fatto che esiste una sessione beacon.

**Correzione architetturale:** capability registry separato per `authorized_lab` e `authorized_engagement`; deny-by-default; manifest firmato con approvatore, finestra, target e budget; test di revoca e kill switch; esecuzione soltanto in fixture o in un profilo esplicitamente attestato. Non considerare l’offuscamento del codice una misura di autorizzazione.

## F-06 — Raccolta media e sensori sensibili

**Severità:** High  
**Area:** beacon headers e C2 artifact handler.  
**Evidenza:** screen capture/recording/stream, camera, audio, GPS e keylogging sono presenti nei file e nelle route di risultato.

Il C2 salva file reali in `data/screenshots`, `data/remote`, `data/recordings` e `data/downloads`. Manca, nei percorsi esaminati, una classificazione uniforme per dati, retention per engagement, quota per beacon e policy obbligatoria per ciascun sensore.

**Correzione:** capability indipendenti con default deny, opt-in esplicito, retention e classificazione. Il server deve rifiutare artifact sopra quota e applicare redazione o cifratura prima della persistenza. I risultati devono avere `artifact_id`, checksum, owner engagement, data classification e delete receipt.

## F-07 — API C2 pubblicabile su `0.0.0.0` con route catch-all

**Severità:** High  
**File:** `phantom/core/c2_server.py`, circa 906 e 1027–1065.

Il server costruisce route per check-in, risultati, queue, artifact/payload e aggiunge handler catch-all per GET/POST. Il listener viene forzato su `0.0.0.0`. L’autenticazione HMAC è applicata ai percorsi beacon specifici, ma la review deve dimostrare che ogni route amministrativa e ogni route di artifact/queue abbia autenticazione e autorizzazione indipendenti.

**Correzione:** bind esplicito e documentato; deny-by-default per route; middleware centralizzato che distingue beacon, operator e artifact client; mTLS o token short-lived per operator API; nessun catch-all che inoltri automaticamente a check-in/result; test matrix route × principal × method.

## F-08 — Token payload in query string e token globale

**Severità:** High  
**File:** `c2_server.py`, circa 732–743; `main.cpp`, circa 823–834.

Il payload token può passare nella query `?auth=TOKEN` e viene incorporato nell’URL costruito dal beacon. Query string e URL possono finire in proxy log, browser history, telemetry o error message. Il token è inoltre usato per più endpoint di payload.

**Correzione:** usare header one-time o mTLS per download; token scoped a beacon/platform/artifact, short-lived e non riutilizzabile; rifiutare query token dopo migrazione; redigere URL nei log.

## F-09 — Remote viewer loopback senza autenticazione propria

**Severità:** High  
**File:** `phantom/core/remote_viewer.py`, circa 189–232.

Il viewer si lega a loopback, scelta positiva, ma `/send` accetta JSON e accoda direttamente `remote input ...` senza session token, nonce, CSRF protection, capability grant o verifica che il browser appartenga all’operatore che ha aperto la sessione. Un altro processo locale o una pagina locale maligna può tentare richieste al listener.

Inoltre il testo UI espone esplicitamente controllo mouse/tastiera e la funzione manda input in-band come comandi beacon.

**Correzione:** session token casuale per viewer, same-origin check, CSRF token, expiry breve, capability separate, input allowlist typed invece di stringhe, audit per enable/disable/input class. Loopback non deve essere considerato una boundary di autenticazione sufficiente.

## F-10 — Remote viewer usa polling non sincronizzato e memoria indefinita

**Severità:** High  
**File:** `remote_viewer.py`, circa 117–134; `c2_server.py`, artifact/live segment handlers.

Il browser usa `setInterval(async ...)` senza impedire richieste sovrapposte e il delay è calcolato al momento della creazione usando il valore iniziale di `live`; il successivo “sync” non cambia realmente l’intervallo. Il C2 conserva frame e live segments in strutture e directory che richiedono una retention/cleanup esplicita.

**Correzione:** event stream o polling seriale con cursor/sequence, AbortController, deduplica e backoff; quota per frame, TTL, cleanup su chiusura sessione e retention per engagement.

# 3. AutoMode, orchestrator e learning

## F-11 — Evolution state non atomico e non process-safe

**Severità:** High  
**File:** `phantom/automation/evolution/loop.py`, circa 56–121.

`EvolutionState` carica e riscrive JSON con `write_text`, senza lock inter-processo, temp file, fsync o revision check. Due AutoMode run o due worker possono superare contemporaneamente `can_gate()`/`can_pr()` e sovrascrivere `cases`, `authored` o contatori.

**Correzione:** SQLite o repository transazionale; lock inter-processo; transizioni atomiche per reservation; revision/compare-and-swap; schema versioning; recovery dopo crash.

## F-12 — Il contatore gate è aggiornato dopo l’esecuzione e non riserva budget atomicamente

**Severità:** High  
**File:** `loop.py`, circa 173–183 e 216–217.

`can_gate()` viene controllato prima dello spawn, ma `count_gate()` è chiamato dopo che il worker ha completato l’author loop. Più worker possono quindi partire oltre il budget giornaliero. Il commento afferma budget hygiene, ma il controllo attuale non è un admission transaction.

**Correzione:** `reserve_gate_slot()` atomico prima dello spawn; rilascio o contabilizzazione esplicita su failure; limite simultaneo di worker; persistenza del job ID e dello stato.

## F-13 — Sandbox di scrittura stretta, ma gate AST insufficiente come isolamento

**Severità:** High  
**File:** `sandbox.py`, `gate.py`.

La write allowlist è un buon controllo: sono consentite solo `phantom/automation/guidance/learned/`, `tests/learned/` e `docs/evolution/`. Tuttavia il gate statico considera lo stdlib ammesso quasi integralmente, incluso `subprocess`, `socket`, `urllib`, `os` e `open`; vieta solo alcuni import top-level e due nodi AST. Il prompt chiede di non scrivere o fare side effect, ma il prompt non è un confine di sicurezza.

Una capability generata potrebbe quindi usare moduli standard per rete, processi o filesystem, anche se non usa import vietati. Il lab obbligatorio riduce il rischio ma non è sandboxing del processo Python.

**Correzione:** eseguire learned capabilities in processo/container separato con seccomp/AppArmor o sandbox equivalente; egress deny di default; filesystem read-only con fixture; resource limits; syscall policy; timeout che termini il process group; capability runtime che esponga adapter sicuri invece di stdlib libero. Il gate AST deve diventare una validazione aggiuntiva, non la boundary primaria.

## F-14 — Auto-load di file learned locali e beta loading di PR aperte

**Severità:** High  
**File:** `phantom/automation/guidance/learned/__init__.py`, circa 37–64; `phantom/automation/evolution/beta.py`, circa 67–194.

Ogni file nella directory learned viene importato a ogni boot. Il beta loader scarica branch di PR aperte, esegue import e aggiunge `CAPABILITY` a `_PENDING` nel processo corrente. Static gate e registry check non equivalgono a un trust boundary: l’import del modulo può produrre side effect prima dell’uso della capability.

Inoltre `_gate_in_checkout()` verifica che esista almeno una capability learned nella registry, non che la specifica capability candidate sia effettivamente presente e quella verificata; `load_beta()` poi importa direttamente il file dalla checkout temporanea.

**Correzione:** non importare codice non trusted nel processo principale; eseguire gate e capability in worker/container separato; verificare ID e digest esatto; approvare esplicitamente PR/commit; mantenere beta fuori dall’AutoMode ordinario; usare signed artifact e allowlist di API runtime.

## F-15 — Evolution author può leggere repository ampio e redazione non completa

**Severità:** Medium/High  
**File:** `sandbox.py`, `llm_advisor.py`.

La sandbox redige pattern comuni e blocca `.env`, sessioni e beacon data. La regex copre però solo alcune forme di secret; la redazione può essere aggirata da formati multilinea, JSON annidato, query string o encoding. Il modello locale riceve dati raw per definizione, mentre il modello remoto riceve un testo redatto ma senza DLP strutturale sui payload binari o artifact referenziati.

Il `world_summary` include anche indicatori come `creds: service valid=...`; è meglio di un valore segreto, ma può trasmettere comunque informazioni sensibili verso il backend remoto.

**Correzione:** schema-based redaction prima dell’LLM; classificazione dei campi; allowlist di record inviabili; secret scanning con entropy e pattern; divieto di inviare raw event text al remote provider; audit della trasformazione; test adversarial su JSON, YAML, log, URL, base64 e multilinea.

## F-16 — LLM advisor include capability operative sensibili nella whitelist

**Severità:** High come rischio di governance  
**File:** `llm_advisor.py`, circa 43–53 e 75–96.

L’LLM è correttamente descritto come non-gating e restituisce solo ID di capability. Tuttavia la whitelist comprende exploitation, RCE foothold, credential-adjacent social capability, lateral pivot, DCSync/roasting e campagne social. Un advisor non-gating può comunque influenzare il ranking e il planner.

**Correzione:** whitelist per profilo di engagement e manifest; capability sensibili escluse dal default; decision record con policy result; test che un LLM suggestion non può introdurre capability assente dal manifest; separazione tra hypothesis generation e admission.

## F-17 — Replanning e background evolution non isolati dal run corrente

**Severità:** High  
**File:** `loop.py`, integrazione AutoMode e experience engine.

Il worker di evolution parte in thread daemon mentre la chain continua. Questo è utile per non bloccare, ma il contratto deve garantire che il nuovo codice, beta capability o learned state non modifichi la registry e il comportamento del run già in corso. La persistenza JSON e l’import dinamico rendono il rischio concreto.

**Correzione:** ogni job deve fissare `engine_commit`, `knowledge_version`, `policy_version` e `registry_digest` all’avvio. Le proposte dell’evolution loop diventano disponibili soltanto a un nuovo job dopo review/merge/canary.

# 4. C2, beacon e autenticazione

## F-18 — Beacon non enrolled ancora accettato quando auth required non è attivo

**Severità:** High in deployment esposto  
**File:** `c2_server.py`, circa 64–75.

Se il beacon non è registrato, `authenticate_beacon()` restituisce `not beacon_auth_required()`. Questo preserva compatibilità ma rende il default dipendente dalla configurazione runtime. Un listener su `0.0.0.0` senza enforcement esplicito può accettare check-in non autenticati.

**Correzione:** production profile fail-closed; bootstrap enrollment separato e one-time; nessun beacon anonimo; alert se `beacon_auth_required` è disabilitato su bind non-loopback.

## F-19 — Nonce HMAC mantenuti solo in memoria

**Severità:** Medium/High  
**File:** `c2_server.py`, circa 59–104.

La replay protection usa `auth_nonces` in memoria. Un riavvio del server perde la history e il counter è volutamente advisory. Il commento spiega il trade-off dopo migration/restart, ma un replay entro la validità temporale può essere rieseguito dopo restart se il payload è riutilizzabile.

**Correzione:** nonce store durevole con TTL o session epoch server-side; counter monotonic per identity con recovery; invalidazione globale al cambio di epoch; task ID idempotenti e signed.

## F-20 — Auto-persist al primo check-in bypassa la policy di sessione

Questo finding è distinto da F-04 lato shell: il server inserisce task prima che il beacon sia stato associato a un engagement manifest. Enrollment e authorization devono essere due passaggi separati.

## F-21 — Task command ancora stringhe non tipizzate

**Severità:** High  
**File:** `C2State.queue_task`, `c2_shell.py`, beacon command dispatcher.

Anche con HMAC, il payload autenticato può essere una stringa arbitraria come `persist`, `remote`, `inject`, `mem-run` o comandi di input remoto. L’autenticazione dimostra chi ha inviato la stringa, non che la capability sia autorizzata per quel beacon.

**Correzione:** task schema con `capability_id`, `args`, `scope_ref`, `expires_at`, `nonce`, `policy_hash`, firma e audit; dispatcher typed; rifiuto dei comandi legacy fuori da un adapter di compatibilità esplicitamente limitato.

## F-22 — Artifact storage senza policy uniforme di quota/classification/retention

**Severità:** High  
**Area:** `C2State.add_result`, screenshot/media/recording handlers.

È positivo che l’output base64 venga convertito in artifact, ma la persistenza locale di screen, camera, audio, GPS e file richiede quota per engagement, classification e TTL. `MAX_RESULT_OUTPUT_BYTES` e `MAX_RESULTS_PER_BEACON` sono limiti di quantità, non una data governance policy.

**Correzione:** `artifact_id`, `engagement_id`, classification, owner, checksum, encryption-at-rest, max bytes per type, TTL, cleanup job e audit access/read/delete.

# 5. Remote session

## F-23 — Viewer professionale come concept, non ancora come security boundary

La feature è fattibile e ha valore operativo, ma l’attuale implementazione è più vicina a un **in-band GUI takeover** che a un servizio remote-session completo. `remote_viewer.py` accoda stringhe `remote input ...`, mentre il beacon scarica/esegue il modulo e il modulo registra un altro beacon.

Per una versione enterprise servono:

- session manifest separato dal beacon command channel;
- view-only default;
- enable separato per mouse, keyboard, clipboard e file transfer;
- session token temporaneo;
- local indicator obbligatorio nei profili ordinari;
- revoca e expiry applicate anche al modulo remoto;
- audit degli eventi di sessione;
- WebRTC o transport equivalente con broker autenticato, se si vuole latenza reale;
- rate/size limits e cleanup dei frame.

## F-24 — CORS/CSRF e content security non esplicitati nel viewer

Le route viewer non mostrano autenticazione, CSP, CSRF token o header di sicurezza. Essendo loopback-only il rischio è ridotto ma non nullo. La pagina può essere aperta da un browser locale e inviare POST al listener se il browser consente la richiesta cross-origin o se il processo locale è raggiungibile.

**Acceptance criteria:** origin randomizzato o token nell’URL non riutilizzabile, CSRF, `Content-Security-Policy`, no inline network destinations, session shutdown che chiude il server.

# 6. Electron e UI

## F-25 — IPC generico e remote actions dalla UI

La precedente criticità resta: `request(method, endpoint, body)` espone un contratto generico. Con C2 dashboard, remote canvas, recordings, vault, payload generation e learning panel, la superficie deve diventare typed e per-capability.

**Correzione:** API preload esplicite; schema validation; endpoint allowlist; request correlation; principal/session context; rifiuto di body con command string; separazione read-only e mutating operations.

## F-26 — Polling sovrapposto e stato incompleto

AutoMode/C2/remote viewer usano polling e stream locali. La UI deve gestire sequence, abort, reconnect, dedup e stati terminali. `running` non basta per distinguere planning, waiting approval, active, stopping, revoked, expired, degraded e failed.

## F-27 — Artifact e viewer non isolati per engagement

Le route viewer leggono directory aggregate come `data/remote` e `data/recordings`. Se l’operatore ha più engagement o più beacon, la UI deve impedire cross-tenant/cross-engagement exposure. Il nome file o beacon non deve essere la sola authorization key.

## F-28 — `sandbox: false` è un trade-off, non un finding autonomo

Il branch può mantenere `sandbox: false` per vincoli runtime, ma deve documentarlo. La mitigazione minima è preload minimale, `contextIsolation`, `nodeIntegration: false`, CSP, navigation/window-open policy, no remote content e IPC typed. La scelta va testata con renderer compromise assumptions.

# 7. API, scope, executor e dati

## F-29 — Scope e target resolution restano aree prioritarie

I finding precedenti restano applicabili finché non sono dimostrati chiusi con test: risoluzione singola hostname, CIDR materializzato prima del limite, scope vuoto fail-open, pivot/redirect target non rivalidati e identity target non coperti da network scope.

Lo scope deve essere congelato per run con A/AAAA resolution, target canonicalization, DNS rebinding defense, egress policy e target derivato rivalidato a ogni side effect.

## F-30 — Checkpoint, workflow e history devono essere transazionali

I precedenti rischi su checkpoint non atomici, workflow globale, WorldModel condiviso e history JSON rimangono rilevanti alla luce del nuovo evolution state. Il job deve fissare uno snapshot immutabile e usare state transition atomiche. Un crash durante un `started` effect non deve causare un doppio effetto al resume.

## F-31 — Report/export e secret redaction devono avvenire prima della persistenza

Il report HTML senza escaping e la possibile propagazione di secret nel trail restano finding applicabili. L’escaping deve avvenire in serializzazione e i secret devono essere eliminati dal modello persistente, non solo mascherati in UI.

# 8. Evolution engine: valutazione positiva e gap

## Punti forti

Il design contiene diversi principi corretti:

1. evolution è off-by-default;
2. il lab è richiesto prima di auto-load e PR;
3. l’autore scrive solo in tre root;
4. i file sono scritti con temp file e replace;
5. il gate è static → registry → units → lab;
6. l’autore LLM riceve un read budget;
7. il codice del motore e i guardrail non sono scrivibili dall’autore;
8. il publish usa worktree separato;
9. il token GitHub è letto da environment;
10. il merge non è automatico;
11. l’auto-load mostra provenance con prefisso `learned.`;
12. i test verificano path traversal e failure del lab.

## Gap principali

Il gate non è un sandbox. Importare codice machine-authored nel processo principale rimane il rischio dominante. La validazione deve avvenire in un processo isolato e l’AutoMode deve usare solo capability firmate e promosse. Il beta loader non dovrebbe caricare ogni PR aperta soltanto perché il branch appartiene a `auto-evolution/`; deve verificare commit, repository, author trust, review status, digest e capability policy.

`publish.py` incorpora il token in una URL Git temporanea (`https://x-access-token:TOKEN@github.com/`). Sebbene il codice eviti di loggare esplicitamente la URL, questa può comparire in process list, debug output, git config temporaneo o error report. Usare `http.extraHeader`, GitHub App installation token o credential helper temporaneo; pulire sempre il contesto.

Il publish crea un branch locale partendo da un branch esistente o lo crea con `git branch`, ma non verifica in modo evidente che la base sia l’ultimo `origin/dev`, che il worktree sia clean o che i file fuori dalla lista autoriale non siano stati modificati. Prima del commit servono diff allowlist e base commit pinning.

Il daily budget e l’idempotence state sono JSON non atomici. Il lab compose ha refcount in memoria e un cleanup che può non avvenire dopo crash. Il lab è utile come behavioural proof, ma non deve essere considerato prova sufficiente per capability che usano filesystem, processi, rete o side effect non rappresentati dal lab.

# 9. Test e CI

## Verifiche eseguite

| Verifica | Esito |
|---|---|
| `git diff --check` | Pass |
| Python `compileall` su `phantom` e `tests` | Pass |
| `pytest --collect-only` | Non eseguibile: `pytest` assente |
| Typecheck Electron | Non eseguito: dipendenze Node non installate |
| C/C++/Android build | Non eseguito |
| Docker lab | Non avviato |
| Runtime C2/beacon | Non avviato |

La suite contiene numerosi test dedicati a evolution, remote module, security hardening, beacon auth e C2. Questo è positivo, ma diversi test verificano che una capability offensiva venga generata o consegnata correttamente, non che la capability sia impossibile fuori dal manifest. Servono più test di **negative authorization**.

## Test mancanti prioritari

| Area | Test necessario |
|---|---|
| C2 | Un beacon non enrolled viene rifiutato su bind non-loopback |
| C2 | Task string legacy viene rifiutata senza capability grant |
| C2 | Replay dopo server restart viene rifiutato o marcato stale |
| C2 | Payload token in query viene rifiutato in production profile |
| C2 | Auto-persist non viene accodata al semplice check-in |
| Remote | POST `/send` senza session token/CSRF viene rifiutato |
| Remote | Session expiry revoca anche input e stream |
| Remote | Artifact di un beacon non è leggibile da altra engagement |
| Evolution | Due processi non superano insieme daily budget |
| Evolution | Capability con `subprocess`, socket non allowlisted o file write viene bloccata a runtime |
| Evolution | Beta PR con ID diverso dal file candidate non viene caricata |
| Evolution | Digest del commit cambia dopo gate → load rifiutato |
| Evolution | Crash durante state save non perde reservation o riapre doppia authoring |
| Scope | Hostname A/AAAA, DNS rebinding e target derived |
| Executor | Timeout elimina process group e figli |
| Electron | IPC endpoint non allowlisted viene rifiutato |
| Secrets | Canary secret assente da event bus, C2 result, artifact, report e PR |
| CI | Build riproducibile con lockfile e artifact provenance |

# 10. Domande aperte da chiarire

Queste domande cambiano materialmente l’architettura e non sono state dedotte con sufficiente certezza dal codice:

1. **Deployment model:** Phantom deve essere single-operator/local-only oppure supportare C2 esposto a Internet, più operatori e più engagement contemporanei?
2. **Enrollment:** un beacon nuovo deve davvero auto-persist e registrarsi automaticamente, oppure era una scorciatoia da laboratorio?
3. **Remote session:** deve essere un modulo visibile di remote support o una sessione operativa stealth? La scelta determina session indicator, approval e transport.
4. **Learning scope:** una capability learned può fare solo recon/observation oppure può diventare `post`, `brute`, `cloud` o `mobile`?
5. **Beta trust:** le PR aperte devono essere eseguibili in `--beta` prima della review oppure solo dopo review/merge?
6. **Cloud LLM:** quali categorie di dati possono lasciare la macchina verso un endpoint remoto? Il solo regex redaction non è una policy sufficiente.
7. **Artifact policy:** per quanto tempo devono restare screenshot, recording, audio, GPS e download? Quale retention vale per engagement?
8. **Authorization source:** esiste un engagement manifest firmato esterno oppure l’autorizzazione è oggi soltanto un flag CLI/operator decision?
9. **Production target:** `lab`, `authorized_engagement` e `research` sono profili distinti a livello di codice o soltanto convenzioni documentali?
10. **Repository automation:** il token evolution è una GitHub App installation token, PAT fine-grained o token generico? Quali branch e permessi ha realmente?

# 11. Roadmap prioritaria

## P0 — bloccare side effect impliciti e confini deboli

1. Disabilitare auto-persist al check-in.
2. Rendere enrollment e authorization distinti.
3. Applicare capability manifest server-side a ogni task beacon.
4. Rimuovere task string generiche dal percorso principale.
5. Fail-closed per beacon non enrolled su listener non-localhost.
6. Separare remote session da C2 task channel e introdurre session token/expiry.
7. Impedire la persistenza di password, OTP, token, cookie e raw sensitive data.
8. Isolare learned/beta capabilities in processo/container separato.

## P1 — rendere affidabile il job/evolution engine

1. Spostare evolution state su SQLite o store transazionale.
2. Riservare atomically gate/PR budget prima dello spawn.
3. Pinning di commit, registry digest e knowledge version per ogni job.
4. Validare diff allowlist prima del commit e della PR.
5. Rimuovere token da URL Git e usare GitHub App/extraHeader.
6. Rendere lab cleanup crash-safe e verificabile.
7. Implementare process group cancellation e bounded worker pool.
8. Rendere checkpoint e history atomicamente versionati.

## P2 — remote session e artifact professionali

1. View-only default.
2. Enable separato per mouse, keyboard, clipboard e file transfer.
3. Local indicator e audit.
4. Session broker con transport autenticato.
5. Artifact manifest, classification, quota, encryption e TTL.
6. Event stream con cursor/sequence invece di polling sovrapposto.

## P3 — validazione e release

1. Installare dipendenze pinned e rendere eseguibile la suite in CI.
2. Aggiungere test negativi di authorization e isolation.
3. Compilare ogni target beacon in CI riproducibile.
4. Firmare artifact e associare SBOM/provenance.
5. Proteggere `dev` e `main`, CODEOWNERS e review obbligatoria per capability sensibili.
6. Separare pacchetti e permessi `emulation`, `authorized_lab`, `authorized_engagement` e `detection`.

# 12. Conclusione

Phantom è diventato un progetto molto più ambizioso e, in alcune aree, meglio ingegnerizzato rispetto alla versione precedente. L’evolution engine è la parte più promettente: il pattern **failure → candidate → gate → lab → branch → PR** è corretto e può produrre miglioramenti progressivi senza modificare direttamente il branch `dev`.

Il rischio principale del branch attuale è che il sistema abbia contemporaneamente **autonomia decisionale, C2, payload delivery, persistenza, remote desktop, raccolta sensori, social delivery e import dinamico di codice learned**. In questa combinazione, audit, HMAC o test isolati non bastano: serve una policy runtime compositiva che impedisca a una singola sessione o token di ereditare capability non approvate.

La raccomandazione professionale è quindi di procedere con due binari distinti:

- stabilizzare e rendere verificabile l’engine: job isolation, state machine, scope, capability manifest, task typed, artifact policy, evolution sandbox reale;
- classificare le capability ad alto impatto come profili espliciti e non-default, con approvazione, revoca, audit e test di non-esecuzione fuori scope.

Il branch è adatto a una fase di **hardening e threat-model review**, non ancora a essere considerato una piattaforma operativa sicura soltanto sulla base dei test attuali.

## References

[1]: https://github.com/Terminalkid09/Phantom/tree/dev "Phantom repository — dev branch"
[2]: https://github.com/Terminalkid09/Phantom/blob/dev/phantom/automation/evolution/loop.py "Phantom evolution loop"
[3]: https://github.com/Terminalkid09/Phantom/blob/dev/phantom/automation/evolution/sandbox.py "Phantom evolution sandbox"
[4]: https://github.com/Terminalkid09/Phantom/blob/dev/phantom/automation/evolution/gate.py "Phantom evolution validation gate"
[5]: https://github.com/Terminalkid09/Phantom/blob/dev/phantom/automation/evolution/publish.py "Phantom evolution branch and PR publisher"
[6]: https://github.com/Terminalkid09/Phantom/blob/dev/phantom/automation/evolution/beta.py "Phantom beta capability loader"
[7]: https://github.com/Terminalkid09/Phantom/blob/dev/phantom/automation/llm_advisor.py "Phantom LLM advisor and redaction"
[8]: https://github.com/Terminalkid09/Phantom/blob/dev/phantom/core/c2_server.py "Phantom C2 server"
[9]: https://github.com/Terminalkid09/Phantom/blob/dev/phantom/core/remote_viewer.py "Phantom remote session viewer"
[10]: https://github.com/Terminalkid09/Phantom/blob/dev/phantom/payloads/beacon/src/main.cpp "Phantom beacon command dispatcher"
[11]: https://github.com/Terminalkid09/Phantom/blob/dev/tests/test_evolution.py "Phantom evolution tests"
[12]: https://github.com/Terminalkid09/Phantom/blob/dev/tests/test_remote_module.py "Phantom remote module tests"
[13]: https://github.com/Terminalkid09/Phantom/blob/dev/tests/test_security_hardening.py "Phantom security hardening tests"
[14]: https://github.com/Terminalkid09/Phantom/blob/dev/.gitlab-ci.yml "Phantom GitLab CI configuration"
[15]: https://github.com/Terminalkid09/Phantom/blob/dev/lab/docker-compose.yml "Phantom local evolution lab"


# 13. Seconda valutazione: valore delle feature e maturità enterprise

## 13.1 Avere molte feature nel C2 non è il problema

La presenza di molte feature nel C2 non è di per sé una criticità. Un control plane professionale può legittimamente avere tasking, enrollment, artifact, health, remote session, recording, payload management, audit, identity rotation e integrazioni con altri sistemi.

La criticità segnalata nell’audit precedente è più precisa: **il control plane deve impedire che una capability erediti automaticamente i privilegi delle altre**. Nel branch attuale esistono percorsi in cui un beacon nuovo genera auto-persist, il task è una stringa, il token è condiviso tra endpoint di payload e il remote viewer accoda input direttamente nel canale C2. Questo non significa che “troppe feature” siano sbagliate. Significa che la composizione delle feature deve essere governata da capability grant separati.

| Aspetto | Valutazione |
|---|---|
| Numero elevato di feature | Non è un problema; può essere un vantaggio |
| Feature modulari con contratti propri | Positivo |
| Un solo token per payload diversi | Debolezza di isolamento |
| Stringhe arbitrarie come task | Debolezza di tipo e policy |
| Auto-persist al primo check-in | Side effect implicito da rimuovere |
| Remote session integrata nel C2 | Valida, ma con session boundary separata |
| Artifact comuni per tutti i beacon | Rischio cross-engagement |

Il giudizio non è “ridurre le feature del C2”. È **mantenere le feature, ma separare control plane, capability plane, artifact plane e authorization plane**.

## 13.2 Analisi del manual core

Il manual core ora dispone di un chain planner in `phantom/core/chain.py`. La pipeline è sensata: proietta il WorldModel in fatti operativi, usa `CompositionEngine`, cerca catene a costo minimo, mostra cost/noise e permette una preview prima dell’esecuzione.

Sono positivi i seguenti aspetti:

- associa gli operatori a capability concrete quando esiste una mappatura;
- mostra il comando costruito prima dell’esecuzione;
- alimenta nuovamente il WorldModel con i finding interpretati;
- dichiara gli step senza mapping manuale come `engine-only`;
- include test per target identitari, report operator/client, ATT&CK mapping e learning evidence.

Restano tre limiti tecnici importanti.

Primo, `execute_step()` restituisce `True` dopo aver chiamato `run_command`, anche se il comando fallisce: interpreta l’output e ritorna comunque una stringa. Il chiamante deve distinguere `command_failed`, `no_findings` e `step_succeeded`.

Secondo, la preview usa `cap.make_command(wm, {})`, mentre l’esecuzione ricostruisce il comando separatamente. Preview ed execution devono condividere `ExecutionContext`, scope snapshot, timeout, policy decision e command digest; altrimenti il comando approvato può differire da quello eseguito.

Terzo, la mappatura include capability post-exploitation e pivot. Non è un errore funzionale, ma ogni categoria deve avere un approval gate distinto: manuale non significa automaticamente fuori policy.

## 13.3 BloodHound: cosa c’è realmente

Nel branch sono presenti `phantom/core/ad_graph.py`, `tests/test_ad_graph.py` e `tests/test_ad_graph_ingest.py`. La feature attuale è meglio descritta come **BloodHound-style local AD graph**, non come integrazione completa con BloodHound/SharpHound.

Il modulo supporta:

- nodi domain, user, group, computer e DC;
- edge `member_of`, `admin_to`, `session`, `cracked` e `owns`;
- ingest di `ad_users`, `ad_user`, `ad_weakness`, `ad_creds` e credenziali domain;
- nesting di gruppi fino a profondità otto;
- BFS verso Domain Admin o un host;
- ereditarietà di edge di potere del gruppo verso gli utenti;
- rendering ASCII e JSON per Electron;
- persistenza locale in `data/ad_graph.json`.

È un miglioramento reale: i test di ingest mostrano che i finding effettivamente prodotti dall’agente possono arrivare al grafo e che il nesting transitive viene trattato. Non ho invece trovato, nel perimetro analizzato, un collector SharpHound completo, un parser JSON BloodHound moderno, un client Neo4j o un query layer compatibile con l’intero modello BloodHound.

| Area | Stato osservabile | Gap enterprise |
|---|---|---|
| Collector | Usa finding già presenti nel WorldModel | Collector BloodHound/SharpHound non verificato |
| Parser | Mapping di finding Phantom | Parser JSON BloodHound moderno non verificato |
| Directory data | Utenti, gruppi e alcune relazioni | ACL, ACE, GPO, trust e delegation incompleti |
| Sessioni | Edge `session` | Temporalità, logon type e freshness da arricchire |
| Computer | Nodi e `admin_to` | RDP, WinRM, DCOM, PSRemote e local-admin non completi |
| Privilegi | Roastability/cracked/admin | GenericAll, WriteDACL, AddMember, DCSync e deleghe non completi |
| Path engine | BFS con nesting e edge curati | Permission-aware semantics e confidence da migliorare |
| Provenance | Source parziale | SID, collector version, timestamp e freshness per edge |
| Scalabilità | Pensato per grafi piccoli | JSON e BFS non ideali per domini molto grandi |

Quindi: **sì, BloodHound è stato aggiunto al manual core in forma locale e utile; no, non è ancora equivalente a una integrazione BloodHound enterprise completa**.

## 13.4 Può funzionare contro target enterprise moderni?

La risposta è differenziata: **alcune parti sono realmente utili in enterprise; altre sono ancora proof-of-concept o dipendono troppo da pattern legacy**. Non definirei l’intero progetto “codice da target del 2000”, ma non è dimostrato che la kill chain completa funzioni contro ambienti moderni.

### Componenti con valore enterprise plausibile

- inventory, fingerprint e network mapping con output strutturato;
- scope e target identity handling, dopo chiusura dei finding precedenti;
- task lease, result deduplication e HMAC beacon auth;
- report operator/client separati;
- threat-intel enrichment e ATT&CK mapping;
- AD graph locale per dati già raccolti;
- evolution gate con lab e PR;
- Electron dashboard per timeline, audit, C2 e learning;
- detection validation e preflight lab.

### Componenti da provare prima di dichiarare compatibilità enterprise

- AD collection con ACL, trust, tiering e grandi volumi;
- hybrid identity, AD Connect, Entra ID e Conditional Access;
- EDR-aware beacon e Windows moderni aggiornati;
- remote session su Windows UAC/secure desktop, macOS permission model e Linux Wayland;
- pivot SSH/WinRM/SMB con segmentazione east-west reale;
- cloud identity e cross-account paths;
- C2 dietro reverse proxy, NAT, proxy autenticati e TLS inspection;
- cleanup dei process tree e resume dopo crash;
- build cross-platform del beacon;
- provider OSINT/social con rate limits e API mutevoli.

La documentazione `docs/PHANTOM_FULL_MANUAL_TEST.md` è utile come regression history, ma la prova su **Metasploitable2** non dimostra maturità enterprise: non rappresenta AD tiering, EDR, Conditional Access, TLS inspection, Windows aggiornati, segmentation, cloud IAM o Kubernetes.

## 13.5 Come misurare davvero la maturità enterprise

Consiglio una test matrix per capability:

| Scenario | Fixture | Metriche |
|---|---|---|
| AD basic | DC, workstation, nested groups | edge coverage, path correctness, false paths |
| AD hardened | LDAP/SMB signing, LAPS, tiering | graceful degradation, evidence quality |
| Hybrid identity | AD Connect, Entra test tenant | identity correlation, freshness, deny behaviour |
| Endpoint | Windows 11 + EDR lab, Linux systemd, macOS permissions | compatibility, detection, cleanup |
| Network | NAT, proxy, segmentation, IPv4/IPv6 | reachability, scope enforcement, timeout |
| Cloud | least-privilege AWS/Azure/GCP fixtures | role graph correctness, secret leakage |
| Web | patched apps, WAF, API gateway | false positive rate, safe probe rate |
| C2 resilience | packet loss, restart, clock skew, duplicate task | idempotence, recovery, delivery |
| Evolution | repeated failure and candidate patches | reproducibility, rollback, guardrail integrity |

Le metriche dovrebbero includere **coverage**, **false positive**, **false negative**, **reproducibility**, **time-to-evidence**, **detection latency**, **cleanup success**, **scope violation count** e **operator review burden**.

## 13.6 Verdetto aggiornato sulla qualità

Non definirei Phantom “codice scarso per target vecchi”. Il repository mostra lavoro reale su contratti, test, modularità, state model e integrazione di più domini. Definirei però il livello attuale **ambizioso ma non ancora provato enterprise end-to-end**.

La qualità è disomogenea:

- **buona** nei contratti e nei test isolati di alcune feature;
- **promettente** in evolution, AD graph e threat-intel enrichment;
- **fragile** nei confini tra C2, task string, remote session e payload;
- **non dimostrata** nei percorsi cross-platform e nelle condizioni di rete/EDR reali;
- **insufficiente per release operativa** finché la suite non è eseguibile e i test negativi di authorization non sono obbligatori.

La prossima review utile dovrebbe prendere 8–12 scenari enterprise autorizzati, eseguirli in un lab riproducibile e misurare ogni passaggio dal finding alla decisione, task, risultato, artifact, detection, cleanup e report.


## 13.7 Verifica runtime mirata dopo la seconda analisi

È stata installata `pytest` e tentata la raccolta mirata di `test_manual_core.py`, `test_ad_graph.py` e `test_ad_graph_ingest.py`. La raccolta ha individuato **19 test**, ma si è interrotta durante l’import di `test_manual_core.py` perché l’ambiente non contiene `rich`:

```text
ModuleNotFoundError: No module named 'rich'
```

È inoltre comparso un `PytestConfigWarning` per l’opzione `asyncio_mode`, dato che il relativo plugin non è disponibile. Questo rafforza il finding sulla riproducibilità: il repository ha una suite ampia, ma il bootstrap delle dipendenze non è ancora sufficientemente deterministico per consentire una verifica pulita su una macchina nuova.

La ricerca dei placeholder ha evidenziato anche adapter intenzionalmente marcati come stub, ad esempio `_idor_adapter` e `_hunt_web_adapter` in `phantom/automation/guidance/kit.py`: non sono necessariamente bug, perché dichiarano che l’esecuzione avviene tramite engine in-process, ma non devono essere conteggiati come comandi manuali realmente disponibili. Questo è un altro motivo per cui l’inventario enterprise deve distinguere tra:

- capability con adapter operativo reale;
- capability eseguita da un engine interno;
- marker stub usato soltanto per mantenere un contratto comune;
- capability che costruisce comandi ma non è stata validata contro un servizio reale.

Il giudizio di efficacia enterprise resta quindi **staticamente plausibile per alcuni sottosistemi, ma non dimostrato end-to-end**. Per una conclusione più forte servono almeno ambiente di dipendenze riproducibile, lab AD/Windows/cloud e test runtime con risultati evidenziati.
