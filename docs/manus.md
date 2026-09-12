# Phantom `dev` — Analisi tecnica approfondita e redesign dell’AutoMode

**Repository analizzato:** `Terminalkid09/Phantom`  
**Branch:** `dev`  
**Data della review:** 8 settembre 2026  
**Tipo di analisi:** review statica approfondita con verifiche sintattiche e lettura dei test disponibili. Non sono stati avviati beacon, C2, payload, moduli di scansione, campagne social o operazioni verso target esterni.

## Executive summary

Il branch `dev` è un refactor molto esteso: rispetto a `main` risultano circa **333 file modificati, 74.206 righe aggiunte e 1.579 rimosse**. La repository contiene una UI Electron articolata, un backend Python locale, un sistema di sessione, un motore AutoMode, un orchestrator multi-agente, moduli OSINT/social, capability post-operation e una componente beacon/C2.

Il progetto ha una base architetturale interessante, ma l’AutoMode non è ancora un sistema enterprise affidabile. Il problema principale non è la mancanza di feature. È la mancanza di un **confine operativo rigoroso** tra pianificazione, autorizzazione, esecuzione, stato, audit e report.

Le criticità più importanti sono:

1. **Esecuzione di comandi shell arbitrari attraverso il bridge API.**
2. **Scope incompleto o fail-open**, soprattutto per hostname risolti, pivot, target identitari e moduli invocabili direttamente.
3. **AutoMode globale e non isolato per job**, con thread concorrenti, stream condiviso e stop non cooperativo.
4. **Limiti multi-agente non realmente applicati**, race condition sul modello condiviso e checkpoint non idempotenti.
5. **Persistenza e export di dati sensibili**, inclusi campi che possono contenere credenziali, senza una politica di minimizzazione e protezione a riposo sufficiente.
6. **Moduli social e post-operation progettati per side effect reali**, senza un Authorization Context tecnico, un egress broker obbligatorio e un confine laboratorio/emulazione verificabile.
7. **Audit non completo e non realmente immutabile** in presenza di più processi, crash o accesso al file.
8. **Electron funzionale ma troppo dipendente da IPC generico e polling**, con lifecycle, cancellazione e contratti di stato da rafforzare.

Non posso aiutare a rendere il tool più efficace in **evasione, phishing operativo, persistenza, C2 offensivo, raccolta credenziali, injection o kill chain autonome abusabili**. Posso però progettare un AutoMode molto più forte come piattaforma di **authorized security validation, emulation, detection engineering, exposure assessment e purple-team automation**, con reasoning enterprise ma con capacità vincolate da policy e audit.

## Classificazione dei finding

| Severità | Significato | Azione consigliata |
|---|---|---|
| Critical | Possibile esecuzione arbitraria, raccolta di segreti o side effect grave | Correzione prima di esporre il componente a utenti o reti operative |
| High | Bypass di scope, perdita di isolamento, race, perdita dati o impatto operativo rilevante | Correzione prioritaria e test di regressione dedicati |
| Medium | Debolezza che degrada audit, affidabilità, sicurezza o determinismo | Correzione nella prossima iterazione architetturale |
| Low | Bug funzionale o inconsistenza con impatto circoscritto | Correzione durante il consolidamento |

# 1. Finding critici

## F-01 — Il bridge API accetta comandi shell arbitrari

**Severità:** Critical  
**File:** `phantom/api/server.py`, circa linee 899–913 e 1122–1135; `phantom/api/backend.py`, circa linee 78–115; `phantom/core/executor.py`, circa linee 619–627.

### Evidenza

Le route `module_run` e `backend_run` ricevono un campo `command` dal JSON del client e lo passano a `BackendDispatcher.run`. Nel backend nativo la stringa arriva a `execute_quiet`, che usa `subprocess.Popen(..., shell=True)`. Il controllo esistente valida alcuni aspetti di `target`, ma non verifica che il comando appartenga a una capability registrata, che gli argomenti siano quelli previsti o che il comando sia semanticamente compatibile con lo scope.

### Impatto

Un renderer compromesso, un token API esposto o un client locale non autorizzato possono trasformare l’API in un esecutore arbitrario sul sistema dell’operatore. Il problema è più grave perché il bridge può interagire con backend nativi, WSL o SSH. Un controllo sul solo target non protegge un comando che contiene altre destinazioni o che non usa affatto il campo target.

### Correzione

Rimuovere gli endpoint generici di esecuzione dal percorso esposto al renderer. Sostituirli con identificatori di capability presenti in un registro immutabile. Il server deve costruire internamente eseguibile e lista di argomenti da uno schema validato, usare `shell=False`, associare ogni argomento a un target canonico e applicare lo scope alla destinazione effettiva. Eventuali operazioni amministrative devono avere un percorso separato, non esposto alla UI ordinaria, con autorizzazione distinta e audit obbligatorio.

## F-02 — Raccolta di password e OTP nel modulo social

**Severità:** Critical  
**File:** `phantom/automation/social/tracker.py`, circa linee 304–325 e 497–519.

### Evidenza

Il modulo genera pagine con campi username, password e OTP e conserva tali valori in strutture di cattura. Il codice e i test descrivono esplicitamente una raccolta di credenziali.

### Impatto

Questa funzionalità può acquisire segreti reali di persone reali. È incompatibile con un modello sicuro di simulazione se non è rigidamente sostituita da account sintetici e segnali non sensibili. Il rischio comprende compromissione di account, responsabilità legale, trattamento illecito di dati e persistenza involontaria nei log o negli export.

### Correzione

Eliminare le route e i campi che accettano password, OTP, cookie, bearer token o session token. Per training autorizzato usare account sintetici, token monouso non riutilizzabili e una pagina trasparente del committente. Il tipo dati del modulo non deve poter rappresentare un segreto. I test devono dimostrare che quei campi vengono rifiutati e che non compaiono in log, audit, report o export.

## F-03 — Impersonazione e omografi nel rendering social

**Severità:** Critical  
**File:** `phantom/automation/social/spoof.py`, circa linee 2–19 e 101–190; `phantom/automation/social/engine.py`, circa linee 960–976.

### Evidenza

Il modulo deriva identità apparenti e applica caratteri omografi per aggirare filtri testuali. Il motore social usa questa trasformazione durante la composizione di mittente e oggetto.

### Impatto

La funzione aumenta intenzionalmente l’efficacia dell’inganno e rende più difficile riconoscere una simulazione. Può facilitare impersonazione di aziende, colleghi o servizi e trasformare un esercizio in una campagna abusabile.

### Correzione

Rimuovere l’uso di omografi e l’impersonazione. Un esercizio deve usare un dominio verificato e controllato dal committente, identificativi della campagna, disclosure coerente con l’ingaggio e destinatari preregistrati. Il valore prodotto dal modulo dovrebbe essere la validazione delle detection, non il superamento dei filtri.

# 2. Finding high: esecuzione, scope e isolamento

## F-04 — Installazione strumenti con input `tool` non allowlisted

**Severità:** High  
**File:** `phantom/core/executor.py`, circa linee 106–177 e 217–243; `phantom/api/server.py`, circa linee 1251–1266.

Il nome dello strumento può arrivare all’endpoint di installazione. Per valori non riconosciuti, l’helper compone una riga di installazione e l’esecuzione usa una shell. Questo consente input inattesi, installazioni non previste e operazioni con privilegi elevati.

La correzione consiste in un catalogo immutabile di ID di strumenti approvati. L’ID deve essere mappato server-side a pacchetto, versione e gestore. L’installazione deve usare argv, non shell, e deve essere isolata dal loop API con timeout e audit.

## F-05 — Scope hostname incompleto e risoluzione non congelata

**Severità:** High  
**File:** `phantom/core/scope.py`, circa linee 14–45.

La verifica hostname usa una sola risoluzione IPv4. Non considera necessariamente tutti gli indirizzi A/AAAA, non congela la risoluzione approvata e permette che il tool risolva nuovamente il nome durante l’esecuzione.

Un hostname può quindi passare il controllo in base a un indirizzo e raggiungere successivamente un altro indirizzo. La correzione deve usare `getaddrinfo`, normalizzare tutte le risoluzioni, valutare IPv4 e IPv6, bloccare DNS rebinding e associare al job una risoluzione canonica con scadenza.

## F-06 — CIDR enorme materializzato prima del limite

**Severità:** High  
**File:** `phantom/core/automode.py`, circa linee 674–688.

`_expand_targets` costruisce `list(net.hosts())` e applica il limite solo successivamente. Una rete molto ampia può quindi essere materializzata interamente prima del controllo.

Il limite deve essere verificato dal prefisso prima dell’espansione oppure con `islice(..., MAX + 1)`. Devono essere imposti anche limiti su numero complessivo di target, dimensione del body, budget temporale e numero di azioni per job.

## F-07 — AutoMode globale, sovrascrivibile e senza cancellazione reale

**Severità:** High  
**File:** `phantom/api/server.py`, circa linee 506–574 e 765–781; `phantom/core/automode.py`, circa linee 840–882.

Ogni chiamata a `/api/automode/run` resetta variabili globali come `_auto_stream`, `_auto_done` e `_auto_current_step`, quindi può mescolare o cancellare lo stato di un run già esistente. Il nuovo lavoro parte in un thread senza un job manager robusto. `/api/automode/stop` imposta uno stato globale, ma non propaga un cancellation token agli executor.

Il renderer può quindi visualizzare un run fermato mentre il backend continua a lavorare. Due run concorrenti possono produrre log, risultati e report incoerenti.

La correzione è un `JobManager` con `job_id`, lock per engagement, stato persistente, policy di concorrenza e token di cancellazione cooperativo. Un secondo run deve essere rifiutato, messo in coda o esplicitamente autorizzato come campagna separata.

## F-08 — Timeout applicato al wrapper, non all’albero di processi

**Severità:** High  
**File:** `phantom/core/executor.py`, circa linee 619–649; `phantom/api/backend.py`, circa linee 122–148.

Il timeout termina il processo padre ma non garantisce la chiusura dei figli. L’uso di shell wrapper rende il comportamento meno deterministico.

Il job deve partire in un process group o sessione dedicata. Alla deadline occorre terminare il gruppo, attendere un grace period, eseguire una terminazione di escalation, fare reap e verificare che non restino figli. Lo stato finale deve distinguere `TIMED_OUT`, `CANCELLED`, `FAILED` e `COMPLETED`.

## F-09 — Path traversal in profili e report

**Severità:** High  
**File:** `phantom/api/server.py`, circa linee 458–501, 1033–1056, 1673–1696 e 2322–2324.

Il nome profilo viene concatenato direttamente a un percorso. Anche target e altri valori vengono incorporati in directory e nomi di report senza applicare sempre una normalizzazione sicura.

I nomi devono essere identificatori, non path. Usare allowlist di caratteri e lunghezza, `Path.resolve()`, verifica che il risultato sia relativo alla directory base e scritture atomiche con permessi restrittivi. I report dovrebbero usare un ID generato e conservare il target solo nei metadati.

## F-10 — Scope fail-open per scope vuoto e target identitari

**Severità:** High  
**File:** `phantom/core/scope.py`; `phantom/automation/agent.py`, circa linee 266–277, 305–314 e 1283–1320.

Lo scope vuoto viene trattato come “tutto consentito”. Email, username e telefono possono risultare sempre ammessi perché lo scope di rete non copre il destinatario. Le capability social possono inoltre essere invocate senza prova tecnica di consenso.

Serve un `AuthorizationContext` firmato e a scadenza che includa engagement ID, tenant, target ammessi, finalità, finestra temporale, budget, approvatori e capability permesse. In assenza di contesto, il comportamento deve essere fail-closed.

## F-11 — Scope non rivalidato per pivot, redirect e host derivati

**Severità:** High  
**File:** `phantom/automation/agent.py`, `phantom/automation/guidance/kit.py`, `phantom/automation/post/lateral.py`.

Il controllo iniziale verifica il target originale ma non sempre la destinazione effettiva di un’azione successiva. Host inseriti negli slot, peer, redirect o risoluzioni derivate possono quindi uscire dal manifest.

Prima di ogni side effect deve essere risolto il target effettivo e deve essere applicata la stessa policy. I pivot devono essere consentiti solo verso nodi già presenti nel manifest o verso fixture di laboratorio attestato.

## F-12 — Moduli post-operation con side effect reali

**Severità:** High  
**File:** `phantom/automation/post/persistence.py`, `privesc.py`, `inject.py`, `lateral.py`; registrazione in `phantom/automation/guidance/kit.py`.

Le capability costruiscono azioni reali di auto-avvio, escalation, injection e pivot. Le precondizioni tecniche non dimostrano che il target sia un laboratorio isolato né che l’autorizzazione sia ancora valida.

Per una piattaforma sicura queste capability devono diventare moduli di emulazione e detection. Devono generare eventi sintetici firmati, fixture, regole di detection e risultati di validazione senza comandi, payload o modifiche sull’endpoint reale.

## F-13 — Simulazione ransomware con modifica e rimozione di file reali

**Severità:** High  
**File:** `phantom/automation/post/ransom_sim.py`, circa linee 64–123; `phantom/automation/guidance/kit.py`, circa linee 2461–2464; `tests/test_automation_impact.py`.

La simulazione cifra file reali, crea artefatti e rimuove gli originali. La descrizione dichiara invece che non vengono cifrati o eliminati. Questa è una contraddizione di sicurezza e di documentazione.

La sostituzione corretta è una simulazione copy-on-write dentro una directory di fixture attestata, uno snapshot usa-e-getta o un file system dedicato. Deve essere impossibile ricevere una directory arbitraria dal renderer.

# 3. Finding high: orchestrazione multi-agente

## F-14 — `max_agents` e `min_agents` non sono applicati

**Severità:** High  
**File:** `phantom/automation/orchestrator.py`, circa linee 50–61 e 150–173; `phantom/automation/agent.py`, circa linee 2381–2433.

L’orchestrator crea un thread per ogni azione estratta. I limiti sono memorizzati ma non usati per imporre un pool bounded. Anche il fan-out per target può creare molti thread daemon.

Questo può esaurire risorse e rende imprevedibili timeout e stop. Occorre sostituire la creazione di thread per azione con un pool a dimensione fissa, applicare backpressure alla coda e validare `1 <= min_agents <= max_agents`. La UI deve mostrare active, queued, deferred e rejected.

## F-15 — `stop()` definito due volte e stop durante pausa potenzialmente bloccato

**Severità:** High  
**File:** `phantom/automation/orchestrator.py`, circa linee 177–181 e 203–215.

La classe definisce `stop()` due volte. La seconda implementazione sovrascrive la prima e non risveglia l’evento di pausa. Se il run è fermo in `_pause.wait()`, l’evento `_stop` può essere impostato senza sbloccare il loop.

Deve esistere una sola implementazione, idempotente e protetta da una macchina a stati. `stop()` deve svegliare tutti i waiter, marcare il run come stopping e completare la transizione a stopped dopo il join o la cancellazione cooperativa.

## F-16 — Lock per target non condiviso tra orchestrator distinti

**Severità:** High  
**File:** `phantom/automation/orchestrator.py`; `phantom/automation/agent.py`, circa linee 2147–2225.

Worker sullo stesso target possono possedere orchestrator distinti e quindi lock distinti. Il `WorldModel` è condiviso ma non thread-safe. La verifica di stato basata sulla lunghezza di liste può attribuire un’azione a un worker diverso.

Serve un coordinatore di campagna unico che possieda lock per target, egress manager e lease. Il `WorldModel` deve offrire snapshot consistenti protetti da `RLock` o da un actor/event loop. I consumer non devono leggere direttamente attributi privati mutabili.

## F-17 — Pause, stop e drain timeout lasciano worker mutanti attivi

**Severità:** High  
**File:** `phantom/automation/orchestrator.py`, circa linee 139–175 e 182–194; `phantom/automation/agent.py`, circa linee 144–152 e 1881–2010.

Il drain timeout può far uscire `run()` mentre worker daemon continuano a modificare stato. Sleep, wait di fase e attese di sessione non ricevono sempre un token di cancellazione.

Il modello deve separare `stop accepting`, `cancel`, `join` e `finalize`. Non bisogna produrre un report finale o un checkpoint coerente finché esistono writer attivi. Ogni attesa deve rispettare deadline e cancellation token.

## F-18 — Checkpoint non atomico, incompleto e senza ledger idempotente

**Severità:** High  
**File:** `phantom/automation/agent.py`, circa linee 1579–1656 e 1985–1994.

Il checkpoint scrive direttamente nel path finale senza temp file, `fsync`, replace atomico o lock. Salva solo una parte dello stato e non registra un’azione con fasi `started` e `committed`. Dopo un crash, un resume può ripetere un effetto esterno già avvenuto.

Usare schema versionato, snapshot sotto lock, temp file, flush, `fsync`, `os.replace`, fsync della directory e idempotency key per ogni action. Le azioni incomplete devono essere riconciliate, non rilanciate automaticamente.

## F-19 — Workflow globale senza isolamento tra run

**Severità:** High  
**File:** `phantom/core/workflow.py`, circa linee 119–169 e 407–461.

Il workflow aggiorna sessione globale, target, knowledge base e risultati condivisi. Due run possono osservare una fase pending ed eseguirla entrambi prima di marcarla attempted. Non esiste uno stato `RUNNING` atomico, run ID o lease di fase.

Workflow, sessione, planner e repository feedback devono essere istanze scoped a un singolo run. Ogni fase deve usare transizioni atomiche `PENDING → RUNNING → SUCCEEDED/FAILED/SKIPPED/CANCELLED`.

## F-20 — History e calibration soggette a lost update

**Severità:** Medium  
**File:** `phantom/core/history.py`, `phantom/core/calibration.py`, `phantom/core/workflow.py`.

Le strutture globali vengono mutate e riscritte in JSON senza lock inter-processo, revisioni monotone o commit atomico coerente.

Usare repository transazionale o lock inter-processo, revisioni, snapshot read-only per la decisione corrente e aggiornamento online separato dalla persistenza batch.

# 4. Finding high/medium: dati, audit e report

## F-21 — Dati sensibili in chiaro e export eccessivo

**Severità:** High  
**File:** `phantom/api/server.py`, circa linee 72–103, 979–1065, 1874–1906 e 2274–2324.

Sessioni, note, cronologia, risultati, vault e possibili password/hash vengono persistiti o inclusi negli export. Non è evidente una politica uniforme di redazione, cifratura a riposo, retention e permessi.

Il modello deve vietare segreti nei tipi di output. Gli export predefiniti devono escludere credenziali e token. I file devono avere permessi 0600/0700; i dati indispensabili devono usare un secret store o cifratura con chiave separata. Ogni campagna deve avere TTL e delete receipt.

## F-22 — Audit operativo incompleto e modificabile dalla cronologia UI

**Severità:** Medium  
**File:** `phantom/api/server.py`, circa linee 425–435 e 1818–1865.

La cronologia client può aggiungere stringhe arbitrarie e `_timeline_events` è una lista in memoria. Le operazioni ad alto impatto non risultano correlate automaticamente a request ID, job ID, scope congelato, decisione di policy ed esito.

Separare history UI e audit. Il server deve generare eventi append-only e redatti. Un evento deve includere `engagement_id`, `job_id`, `action_id`, capability, decisione allow/deny, scope version, timestamp, outcome e quantità di dati, senza segreti.

## F-23 — AuditLog non protetto tra processi

**Severità:** High  
**File:** `phantom/utils/audit_log.py`, circa linee 45–70 e 74–103.

Il lock è di istanza e non coordina processi diversi o più istanze sullo stesso file. `tail()` e `verify()` possono osservare una scrittura parziale. La hash chain non è firmata né ancorata esternamente.

Usare un writer serializzato con lock inter-processo, append e `fsync`, oppure un backend append-only transazionale. Per requisiti di integrità più forti usare ancoraggi firmati periodici o un archivio esterno. La documentazione deve distinguere integrità della catena da non-ripudio.

## F-24 — Report HTML senza escaping

**Severità:** Medium  
**File:** `phantom/api/server.py`, circa linee 1047–1055 e 1687–1695.

Target, note, risultati e cronologia vengono inseriti in HTML senza escaping. Un input controllato può manipolare il documento e, in certi contesti di apertura, introdurre markup attivo.

Usare auto-escaping o testo semplice. Se si produce HTML, applicare CSP senza script inline e testare payload HTML nei campi di input.

# 5. Finding medium/low: Electron, IPC e UI

## F-25 — IPC generico troppo ampio

**Severità:** High  
**File:** `electron/electron/preload.ts`, circa linee 17–27; `electron/electron/main.ts`, circa linee 206–249.

Il preload espone `request(method, endpoint, body)` e il main process inoltra endpoint arbitrari al backend locale. `contextIsolation` e `nodeIntegration: false` sono buone impostazioni, ma l’API generica rende difficile applicare allowlist, schema e autorizzazioni per operazione.

Esporre API tipizzate come `createJob`, `getJob`, `cancelJob`, `planJob`, `approveJob` e `getEvents`. Validare path, metodo, dimensione body e schema nel main process. Rifiutare endpoint non previsti.

## F-26 — Polling AutoMode con richieste sovrapposte

**Severità:** Medium  
**File:** `electron/src/components/AutoModePanel.tsx`, circa linee 132–161; `electron/src/hooks/useApi.ts`, circa linee 40–52.

`setInterval` crea richieste ogni 800 ms senza attendere la precedente. Una risposta lenta può quindi sovrapporsi alla successiva, duplicare eventi o aggiornare lo stato fuori ordine. Il cleanup cancella l’intervallo ma non abortisce necessariamente la request attiva.

Preferire SSE o WebSocket locale con `sequence number`, oppure un loop asincrono seriale. Aggiungere `AbortController`, deduplica per event ID e gestione di reconnect/backoff.

## F-27 — Stato UI non sufficientemente ricco per il lifecycle del job

**Severità:** Medium  
**File:** `electron/src/store/index.ts`, circa linee 56–76; `AutoModePanel.tsx`.

Lo stato espone `running: boolean`, `current_step`, lista step e reasoning, ma non rappresenta job ID, revision, sequence, deadline, heartbeat, stopping, cancelled, timed out, error code o scope version.

Usare una discriminated union per il job state. La UI deve distinguere `idle`, `planning`, `awaiting_approval`, `running`, `pausing`, `paused`, `stopping`, `cancelled`, `failed`, `timed_out` e `completed`.

## F-28 — Lifecycle del backend locale incompleto

**Severità:** Medium  
**File:** `electron/electron/main.ts`, circa linee 82–145 e 259–268.

`stopApiServer()` invia `SIGTERM` e azzera il riferimento subito. Non attende `close`, non gestisce process group e non ha escalation temporizzata. Se il backend crea figli, questi possono restare attivi.

Implementare shutdown coordinato: stop accepting, cancel job, attendere quiescenza, terminare process group, timeout di escalation, verifica dei figli e solo dopo `app.quit()`.

## F-29 — Gestione errore HTTP perde lo status originale

**Severità:** Medium  
**File:** `electron/electron/main.ts`, circa linee 241–249.

`response.json()` viene invocato indiscriminatamente. Una risposta vuota o non JSON genera un’eccezione e viene restituita come `status: 0`, anche se l’HTTP status originario era informativo.

Leggere prima `content-type`, gestire JSON e testo separatamente e restituire sempre `status`, `request_id`, `error_code` e messaggio sanitizzato.

## F-30 — Sandbox Electron disabilitata e CSP non verificata nella review

**Severità:** Medium  
**File:** `electron/electron/main.ts`, circa linee 156–161.

`contextIsolation: true` e `nodeIntegration: false` riducono il rischio, ma `sandbox: false` aumenta l’impatto di una compromissione del renderer. La review non ha verificato una CSP rigorosa applicata alla pagina.

Valutare `sandbox: true`, blocco della navigazione esterna, gestione controllata dei link, `setWindowOpenHandler`, CSP restrittiva e nessun contenuto remoto non necessario.

## F-31 — Bug funzionale nel riconoscimento web

**Severità:** Low  
**File:** `phantom/core/automode.py`, circa linee 310–316.

Le porte vengono memorizzate come interi ma confrontate con stringhe. Una porta web non standard può quindi non attivare la fase prevista, che viene marcata come completata o saltata in modo ambiguo.

Definire uno schema `Service` tipizzato, confrontare interi e distinguere `SKIPPED_NO_SERVICE` da `COMPLETED` e `FAILED`.

# 6. Analisi per area richiesta

## 6.1 AutoMode e reasoning

Il reasoning enterprise non deve essere una stringa di pensiero mostrata integralmente all’operatore. Deve essere un **decision record strutturato**. Per ogni decisione il sistema dovrebbe memorizzare:

| Campo | Scopo |
|---|---|
| `decision_id` | Identifica la decisione in modo stabile |
| `job_id` e `phase_id` | Collega la decisione al run e alla fase |
| `observation_refs` | Riferisce evidenze già raccolte |
| `hypothesis` | Descrive l’ipotesi tecnica verificabile |
| `confidence` | Indica la confidenza, senza trasformarla in verità |
| `alternatives` | Elenca spiegazioni alternative |
| `risk` | Descrive il rischio dell’azione proposta |
| `policy_check` | Mostra la decisione del policy gate |
| `next_action` | Indica la capability non offensiva da valutare |
| `stop_condition` | Definisce quando fermarsi |
| `review_required` | Indica se serve approvazione umana |

Il planner deve produrre un piano dichiarativo e non comandi. Il piano deve essere verificabile, versionato e sottoposto a policy prima dell’esecuzione. L’AutoMode deve preferire osservazione, validazione, detection e report rispetto a escalation automatica.

Un piano sicuro può contenere fasi come:

1. validazione dell’Authorization Context;
2. normalizzazione e congelamento dello scope;
3. inventory passivo degli asset autorizzati;
4. fingerprint non invasivo con budget;
5. correlazione di esposizioni e misconfigurazioni;
6. verifica di detection tramite emulation locale;
7. raccolta di evidenze minimizzate;
8. report e remediation;
9. approvazione per eventuali test controllati su fixture di laboratorio.

Non dovrebbe contenere fasi autonome di credential harvest, phishing reale, persistenza, C2, evasione o injection.

## 6.2 Agenti multipli

Gli agenti multipli devono essere organizzati per **specializzazione e isolamento**, non per aumentare indiscriminatamente l’azione sul target. Una topologia sicura è:

| Agente | Responsabilità | Output |
|---|---|---|
| Asset agent | Normalizzazione inventory e scope | Asset canonici |
| Exposure agent | Correlazione versioni, configurazioni e advisory | Finding candidati |
| Detection agent | Generazione e validazione di regole | Detection test |
| Evidence agent | Verifica qualità e minimizzazione | Evidenze redatte |
| Report agent | Sintesi tecnica ed executive | Report versionato |
| Policy agent | Allow/deny e richieste di approvazione | Decision record |

Tutti devono usare un `RunContext` immutabile, un `WorldModel` con snapshot e un event bus. Solo un coordinator può concedere lease e accesso all’egress broker. Gli agenti non devono leggere o modificare direttamente la coda interna o gli attributi privati degli altri.

Ogni action deve avere:

- `action_id` e `idempotency_key`;
- capability ID e versione;
- target canonico e scope version;
- deadline e budget;
- precondizioni;
- stato transazionale;
- evidenze prodotte;
- risultato redatto;
- policy decision;
- retry policy;
- cancellation token.

## 6.3 OSINT

Il requisito OSINT è legittimo in un red-team autorizzato e non deve essere eliminato dal prodotto. Il problema rilevato non è l’esistenza del modulo, ma l’assenza di una separazione abbastanza forte tra raccolta autorizzata, PII, dati di breach e uso operativo successivo. Un OSINT enterprise dovrebbe quindi avere profili distinti:

- `passive_asset_osint`, per domini, certificati, DNS e metadati pubblici;
- `authorized_identity_osint`, soltanto per identità e contatti presenti nel manifest;
- `breach_exposure`, limitato a indicatori non sensibili e fonti approvate;
- `case_correlation`, per correlare evidenze senza trasformarle in un dossier operativo indiscriminato.

Il requisito operativo può essere quindi mantenuto, ma ogni query deve essere legata a engagement, scopo, fonte, retention e policy decision. Occorre separare:

- dati pubblici tecnici dell’asset;
- PII personale;
- informazioni di breach;
- dati provenienti da provider esterni;
- dati derivati dal ragionamento.

Il sistema deve applicare data classification, minimizzazione, retention e cancellazione verificabile. Breach lookup e dossier non devono importare password in chiaro né usare dati personali per rendere più persuasiva una campagna. Il risultato può essere dettagliato per il cliente autorizzato, ma deve essere un caso versionato e access-controlled, non un archivio globale riutilizzabile tra engagement.

## 6.4 Phishing e social

Il phishing simulato e il social engineering possono essere componenti legittime di un assessment autorizzato ad alto livello. La distinzione importante è tra **supportare un esercizio approvato** e **ottimizzare l’inganno come capacità general-purpose**. Nel primo caso l’AutoMode può orchestrare un campaign plan, selezionare destinatari già autorizzati, gestire finestre temporali, attendere approvazioni e correlare le detection. Non deve però trasformare credenziali reali, impersonazione o bypass dei filtri in primitive riutilizzabili fuori dall’engagement.

Per mantenere il requisito operativo con un livello enterprise, il profilo social dovrebbe imporre:

- dominio controllato dal committente;
- destinatari preregistrati e verificati;
- modalità console-only predefinita;
- preview e approvazione a quattro occhi;
- rate limit e quota per engagement;
- quiet hours, opt-out e kill switch;
- disclosure coerente con l’ingaggio;
- token sintetici non riutilizzabili;
- nessun campo password, OTP o cookie;
- metriche aggregate di consegna, click e training;
- audit di consenso, policy e cancellazione.

La modalità più autonoma può essere autorizzata dopo la validazione del manifest, ma deve restare vincolata a dominio, destinatari, quota, finestra temporale, template approvati, canali ammessi e kill switch. L’autonomia deve automatizzare il workflow autorizzato, non decidere autonomamente di ampliare il bersaglio o aumentare l’intensità.

## 6.5 Reverse identity resolution e account correlation OSINT

Il termine corretto, nel contesto descritto, è **reverse identity resolution**, **cross-platform account correlation** o **public-account discovery**. Non si tratta di reverse engineering di binari. L’obiettivo è partire da un’identità o da un profilo autorizzato e verificare se esistono altri account pubblici collegabili alla stessa persona, includendo segnali pubblici come username riutilizzati, bio, domini, avatar, riferimenti pubblici, commenti, storie pubbliche, tag e relazioni esposte pubblicamente.

Questa può essere una capability OSINT legittima in un engagement autorizzato, ma è anche l’area con il rischio più alto di **falsa correlazione, invasione della privacy e identificazione di soggetti non inclusi nell’ingaggio**. Il progetto dovrebbe quindi trattarla come un motore di ipotesi e verifica, non come un sistema che dichiara automaticamente che due account appartengono alla stessa persona.

### Modello operativo sicuro

Il modulo dovrebbe:

1. partire da un `subject_id` autorizzato e da un manifest con piattaforme, account e finalità;
2. raccogliere soltanto contenuti pubblici accessibili senza bypass di privacy, login non autorizzati, CAPTCHA evasion o tecniche di accesso riservato;
3. generare candidati con motivazioni e confidence score separando ogni evidenza dalla conclusione;
4. distinguere `same_account`, `possible_match`, `related_entity` e `unverified`;
5. trattare amici, follower, commentatori e persone taggate come soggetti terzi, non come target automaticamente autorizzati;
6. richiedere un nuovo scope o una revisione umana prima di espandere la raccolta a un terzo;
7. conservare URL, timestamp, fonte e hash dell’evidenza senza duplicare più PII del necessario;
8. applicare retention breve, pseudonimizzazione, redazione e cancellazione verificabile.

Il motore non dovrebbe usare una singola coincidenza come prova. Un’ipotesi di correlazione deve indicare quali segnali indipendenti la sostengono, quali alternative esistono e quali dati mancano. Username uguale, avatar simile o una relazione sociale isolata non sono sufficienti per attribuire un account a una persona.

### Gestione di commenti, storie e tag

Commenti, storie pubbliche e tag possono essere indicizzati come **evidenze pubbliche temporali**, ma il sistema deve rispettare la visibilità effettiva e le policy della piattaforma. Non deve tentare di vedere storie private, aggirare controlli, usare account falsi per ottenere accesso o sfruttare amici e contatti come vettori per raggiungere un profilo non pubblico.

I tag di amici e le relazioni pubbliche possono produrre un candidato o un contesto, ma non devono autorizzare automaticamente l’AutoMode a profilare, contattare o collezionare dati sul soggetto collegato. Il risultato corretto è una voce come `related_public_entity` con un blocco policy e una richiesta di approvazione, non l’espansione silenziosa dello scope.

### Struttura dati consigliata

```json
{
  "subject_id": "sub-...",
  "candidate_account": {
    "platform": "example",
    "handle": "public-handle",
    "url": "https://..."
  },
  "classification": "possible_match",
  "confidence": 0.72,
  "evidence_refs": ["ev-1", "ev-2"],
  "alternative_explanations": ["shared alias", "reused avatar"],
  "third_party": true,
  "scope_state": "review_required",
  "retention_until": "..."
}
```

Per l’AutoMode il modulo può lavorare autonomamente sulla raccolta di dati pubblici già autorizzati e sulla deduplicazione, ma la decisione di identificazione e ogni espansione verso terzi devono restare spiegabili, auditabili e soggette a policy. Questa è una forma di autonomia utile e realistica senza trasformare il prodotto in uno strumento general-purpose di tracciamento personale.

## 6.6 Stealth, aggressive e autonomia

La modalità stealth può avere un significato legittimo: **ridurre rumore, rispettare rate limit, minimizzare l’impatto e scegliere controlli passivi o non invasivi**. La modalità aggressive può significare **usare il budget autorizzato in modo più rapido o più completo**, non eludere EDR, nascondere attività, persistere o bypassare controlli.

Per evitare ambiguità, consiglio di separare due assi invece di un unico flag:

| Asse | Valori sicuri | Effetto |
|---|---|---|
| Impatto | `passive`, `low-impact`, `controlled-active`, `lab-impact` | Definisce il tipo di interazione consentito |
| Autonomia | `manual-gate`, `approval-batch`, `authorized-autonomous` | Definisce quanta supervisione è richiesta |

Il vecchio `stealth` dovrebbe quindi essere migrato a un profilo policy, ad esempio `low-impact`, mentre `aggressive` dovrebbe diventare `controlled-active` con budget e capability espliciti. Nessun flag della UI deve poter attivare da solo evasione, persistenza, credential capture, C2 o espansione dello scope.

L’autonomia dell’AutoMode rimane il concetto centrale: il sistema può classificare, pianificare, scegliere tra capability consentite, distribuire agenti, gestire retry, fermarsi su stop condition, generare richieste di approvazione e produrre report. La policy gate deve però essere **non bypassabile e server-side**.

# 7. Architettura AutoMode raccomandata

## 7.1 Componenti

```text
Electron Renderer
        |
Typed Preload API
        |
Electron Main: allowlist + request correlation
        |
Local API
        |
Job Manager ---- Policy & Authorization Context
        |                         |
Planner ------------------ Scope Snapshot
        |
Approval Gate
        |
Bounded Executor ---- Egress Broker / Lab Adapter
        |
Event Store + Checkpoint Repository
        |
Projection API ---- UI timeline and reports
```

## 7.2 Run manifest

Ogni job deve congelare un manifest immutabile:

```json
{
  "schema_version": 1,
  "engagement_id": "eng-...",
  "job_id": "job-...",
  "scope_version": "scope-...",
  "targets": [],
  "allowed_capabilities": [],
  "mode": "authorized-validation",
  "impact_profile": "low-impact",
  "autonomy_profile": "authorized-autonomous",
  "environment": "lab-or-approved-engagement",
  "expires_at": "...",
  "budgets": {
    "max_targets": 20,
    "max_workers": 4,
    "max_duration_seconds": 1800,
    "max_external_requests": 0,
    "max_social_recipients": 0,
    "max_osint_records": 500,
    "max_sample_runtime_seconds": 300
  },
  "approvers": [],
  "approved_channels": [],
  "approved_recipients": [],
  "approved_templates": [],
  "policy_hash": "..."
}
```

I budget devono essere valorizzati dal policy engine in base al profilo, non scelti liberamente dal renderer. Per esempio, un engagement social autorizzato può avere `max_external_requests` e `max_social_recipients` maggiori di zero, ma soltanto se esistono destinatari, canali, template, finestra e approvazioni nel manifest. Il renderer non deve poter modificare il manifest dopo l’approvazione. Il backend deve rifiutare target, capability o budget non presenti.

## 7.3 Macchina a stati

### Job

`NEW → PLANNING → AWAITING_APPROVAL → RUNNING → PAUSING → PAUSED → STOPPING → TERMINAL`

Gli stati terminali sono `COMPLETED`, `FAILED`, `CANCELLED` e `TIMED_OUT`.

### Action

`PENDING → ADMITTED → RUNNING → COMMITTING → SUCCEEDED`

Alternative terminali: `FAILED`, `SKIPPED`, `CANCELLED`, `TIMED_OUT`, `REJECTED`.

Ogni transizione deve essere validata e registrata. Non usare un solo booleano `running` come fonte di verità.

## 7.4 Eventi

Ogni evento deve includere `event_id`, `sequence`, `job_id`, `action_id`, `type`, `timestamp`, `schema_version`, `severity`, `redaction_class` e payload tipizzato. Il client deve applicare gli eventi solo se la sequence è successiva all’ultima ricevuta. Gli eventi duplicati devono essere innocui.

## 7.5 Job API

Una superficie API minima e tipizzata:

| Metodo | Route | Funzione |
|---|---|---|
| POST | `/api/jobs/plan` | Genera piano senza side effect |
| POST | `/api/jobs` | Crea job con manifest congelato |
| GET | `/api/jobs/{id}` | Restituisce projection dello stato |
| GET | `/api/jobs/{id}/events?after=` | Restituisce eventi sequenziali |
| POST | `/api/jobs/{id}/approve` | Approvazione esplicita |
| POST | `/api/jobs/{id}/pause` | Blocca nuove ammissioni |
| POST | `/api/jobs/{id}/cancel` | Cancella cooperativamente |
| POST | `/api/jobs/{id}/resume` | Riprende da checkpoint valido |
| GET | `/api/jobs/{id}/report` | Report redatto e versionato |

Nessuna di queste route deve accettare una stringa shell generica.

# 8. Piano di miglioramento per priorità

## P0 — blocco dei rischi immediati

1. Rimuovere o disabilitare gli endpoint di comando generico.
2. Rendere phishing/social, OSINT e reverse analysis capability governate da manifest e policy, anziché rimuoverle indiscriminatamente.
3. Eliminare la raccolta di password/OTP e l’impersonazione non necessaria; per l’esercizio usare dati sintetici, domini controllati e template approvati.
4. Disabilitare side effect post-operation fuori da fixture di laboratorio o da un profilo esplicitamente attestato.
5. Rendere scope e Authorization Context fail-closed.
6. Vietare password, OTP, cookie e token nei modelli dati e negli export.
7. Correggere la simulazione ransomware per impedirne l’accesso a path arbitrari.

## P1 — correttezza del job engine

1. Introdurre Job Manager e Run Context isolati.
2. Applicare davvero `max_agents` con pool bounded.
3. Rimuovere il doppio `stop()` e implementare cancellation cooperativa.
4. Rendere `WorldModel` thread-safe o actor-owned.
5. Introdurre action ID, lease, idempotency key e stati transazionali.
6. Rendere checkpoint atomici, versionati e riconciliabili.

## P2 — contratto Electron/API

1. Sostituire l’IPC generico con API tipizzate.
2. Sostituire il polling con eventi sequenziali o polling seriale con cursore.
3. Aggiungere schema validation runtime.
4. Migliorare shutdown del backend e gestione dei process group.
5. Valutare `sandbox: true`, CSP, blocco navigazione e window-open policy.
6. Distinguere in UI planning, approval, running, stopping, cancelled e timed out.

## P3 — audit e dati

1. Separare cronologia UI da audit server-side.
2. Applicare locking inter-processo e durabilità al log.
3. Aggiungere redazione, TTL e delete receipt.
4. Proteggere file e directory con permessi restrittivi.
5. Implementare export minimizzato e cifrato solo su richiesta esplicita.
6. Correlare ogni decisione ad engagement, job, action e scope version.

## P4 — qualità enterprise

1. Aggiungere test di concorrenza con barrier e failure injection.
2. Aggiungere test negativi di scope, policy, secret rejection e traversal.
3. Aggiungere test di crash recovery e idempotent resume.
4. Rendere CI riproducibile con dipendenze pinned.
5. Separare pacchetti `emulation`, `authorized_lab` e `detection`.
6. Documentare chiaramente capacità, limiti e precondizioni reali.

# 9. Test plan dettagliato

| Area | Test | Criterio di successo |
|---|---|---|
| API | Comando non registrato | Rifiuto prima di subprocess |
| API | `tool` non allowlisted | Rifiuto senza installazione |
| Scope | Host con A/AAAA misti | Ammesso solo con risoluzione coerente |
| Scope | DNS rebinding | Job rifiutato o target pinning invariato |
| Scope | Pivot verso peer fuori manifest | Rifiuto fail-closed |
| AutoMode | Due run concorrenti | Conflitto o isolamento completo |
| AutoMode | Stop durante pausa | Wake-up e stato terminale |
| AutoMode | Stop con worker lento | Nessun writer dopo finalize |
| Orchestrator | 1000 action | Active sempre `<= max_agents` |
| WorldModel | Stress read/write | Snapshot coerenti, nessun update perso |
| Checkpoint | Crash durante write | JSON precedente o nuovo valido |
| Resume | Action started/non committed | Reconciliation, non doppio effetto |
| Audit | Due processi in append | Sequence e catena coerenti |
| Audit | Verify durante append | Nessuna lettura di riga parziale |
| Secrets | Password/OTP/cookie in input | Rifiuto e assenza in tutti gli output |
| Export | Campagna con dati sensibili | Redazione e policy esplicita |
| HTML | Input con markup | Serializzato come testo |
| Social | Nessun Authorization Context | Default deny |
| Social | Quota superata | Egress bloccato e auditato |
| Lab impact | Path arbitrario | Rifiuto fuori fixture attestata |
| Electron | Backend non raggiungibile | Stato errore coerente, nessun loop infinito |
| Electron | Risposta non JSON | Status HTTP conservato |
| Electron | Reconnect eventi | Deduplica e recupero da sequence |

# 10. Cosa non è stato verificato

Non sono stati eseguiti backend, C2, beacon, payload, scansioni, phishing, tracker o moduli post-operation. Non sono stati installati `node_modules` o dipendenze Python. Il typecheck completo Electron non è stato eseguito perché `node_modules` non era presente. `pytest` non era installato. La compilazione sintattica dei moduli analizzati dagli agenti è riuscita; alcuni test `unittest` di base dell’orchestrator sono passati, ma la suite completa non è stata validata in un ambiente riproducibile.

Il workflow parallelo ha completato tre filoni su quattro; il filone Electron/UX si è interrotto per esaurimento dei crediti della sessione. La relativa analisi è stata quindi ricostruita staticamente dai file principali già esaminati, ma non va considerata una sostituzione di una suite Electron completa.

# Conclusione

Phantom può diventare una piattaforma molto più solida senza negare il contesto reale dei red-team autorizzati. Il salto di qualità consiste nel trasformare l’AutoMode in un **motore autonomo di decisione e validazione autorizzata**, capace di orchestrare OSINT, social engineering simulato, reverse analysis, attività a basso impatto e test attivi consentiti dal manifest. La differenza è che stealth, aggressive e autonomia devono essere policy server-side con budget, destinatari, canali, scope, approvazioni e stop condition verificabili; non devono essere semplici interruttori della UI.

Il reasoning può essere di livello enterprise se il sistema sa distinguere osservazioni, ipotesi, confidenza, alternative, policy, stop condition ed evidenze. L’autonomia può essere elevata quando sceglie e coordina soltanto capability già autorizzate, e quando ogni side effect è correlato a un engagement verificabile. La professionalità si misura nella capacità di operare con precisione dentro un perimetro approvato, produrre risultati riproducibili e fermarsi correttamente quando l’evidenza o la policy non sono sufficienti.

## References

[1]: https://github.com/Terminalkid09/Phantom/tree/dev "Phantom repository — dev branch"
[2]: https://github.com/Terminalkid09/Phantom/blob/dev/electron/electron/main.ts "Phantom Electron main process"
[3]: https://github.com/Terminalkid09/Phantom/blob/dev/electron/electron/preload.ts "Phantom Electron preload bridge"
[4]: https://github.com/Terminalkid09/Phantom/blob/dev/phantom/api/server.py "Phantom local API server"
[5]: https://github.com/Terminalkid09/Phantom/blob/dev/phantom/core/automode.py "Phantom AutoMode core"
[6]: https://github.com/Terminalkid09/Phantom/blob/dev/phantom/automation/orchestrator.py "Phantom automation orchestrator"
[7]: https://github.com/Terminalkid09/Phantom/blob/dev/phantom/automation/agent.py "Phantom automation agent"
[8]: https://github.com/Terminalkid09/Phantom/blob/dev/phantom/utils/audit_log.py "Phantom audit log"
[9]: https://github.com/Terminalkid09/Phantom/blob/dev/phantom/automation/social/tracker.py "Phantom social tracker"
[10]: https://github.com/Terminalkid09/Phantom/blob/dev/tests/test_automation_impact.py "Phantom automation impact tests"
