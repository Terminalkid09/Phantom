# Phantom `dev` — Master Review Handoff for DeepSeek / GLM

## Obiettivo

Eseguire una review indipendente, completa e tecnicamente verificabile del repository `Terminalkid09/Phantom`, branch `dev`.

Questo documento unisce il contesto del progetto, i requisiti funzionali dichiarati dal proprietario, i finding già emersi e le aree che devono essere verificate o migliorate. Non deve essere usato per produrre una lista generica di raccomandazioni: ogni conclusione deve essere collegata a file, linee, precondizioni, test e livello di confidenza.

La review deve distinguere quattro categorie:

1. **bug funzionali confermati**;
2. **rischi di sicurezza o governance confermati**;
3. **hardening teorico o rischio di abuso**, che non è automaticamente un bug;
4. **funzionalità non ancora dimostrate end-to-end**.

Non classificare una feature come difettosa soltanto perché è potente o offensiva. Verificare invece se è implementata correttamente, se è coerente con il contratto dichiarato, se gestisce failure e cleanup e se rispetta scope e autorizzazione.

## Contesto e correzioni del proprietario

### Beacon

Il proprietario dichiara che il beacon è stato testato su sistemi propri e che, nei test effettuati, **non è stato rilevato**. Questo risultato deve essere riportato come evidenza empirica del test specifico.

Non bisogna dichiarare che il beacon viene sicuramente rilevato senza una prova. Bisogna invece distinguere tra:

- risultato osservato nel test del proprietario;
- ambiente, versione e configurazione specifica;
- generalizzazione a sistemi operativi, policy ed EDR differenti;
- gestione del caso in cui il beacon venga terminato, sospeso, quarantinato o perda connettività;
- qualità delle evidenze e del cleanup.

Non è richiesto progettare bypass, evasione o tecniche per eludere prodotti di sicurezza. È richiesto valutare compatibilità, affidabilità, stato, failure handling, detection reporting e cleanup in lab autorizzati.

### Remote session

La remote session deve consentire **interazione reale con il desktop**, inclusi mouse e tastiera. L’input remoto non è un bug e non deve essere rimosso o trasformato in una feature view-only.

La review deve invece verificare:

- correttezza dell’input;
- coordinate, scaling e focus;
- sincronizzazione tra frame e input;
- latenza, perdita e duplicazione di eventi;
- session lifecycle;
- scadenza e revoca;
- audit;
- autenticazione dell’operatore;
- sicurezza del viewer;
- UAC/secure desktop, X11/Wayland e permission model per piattaforma;
- cleanup e comportamento dopo disconnessione.

### C2

Il numero di feature C2 non è considerato un problema. Un control plane completo può gestire tasking, enrollment, health, artifact, remote session, recording, payload, audit, key rotation e più tipi di beacon.

Il punto da verificare è la separazione tra:

- control plane;
- capability plane;
- authorization plane;
- artifact plane;
- remote-session plane.

Non proporre di rimuovere feature solo perché sono numerose. Verificare invece task typing, capability grants, token scope, route authorization, audit, isolamento tra engagement e failure handling.

## Metodo obbligatorio

Analizza il repository reale, non soltanto README e documentazione. Per ogni finding restituisci:

| Campo | Contenuto richiesto |
|---|---|
| ID | Identificatore stabile |
| Severità | Critical, High, Medium, Low, Informational |
| Categoria | Bug, security, governance, hardening, maturity |
| File/linee | Riferimento preciso |
| Evidenza | Comportamento osservabile nel codice |
| Precondizioni | Cosa deve accadere per riprodurlo |
| Impatto | Conseguenza tecnica concreta |
| Confidenza | Alta, media o bassa |
| Correzione | Modifica proposta |
| Test di chiusura | Test specifico verificabile |
| Requisiti preservati | Cosa non deve essere rimosso |

Segnala esplicitamente quando una conclusione deriva soltanto dall’analisi statica. Non confondere un comando costruito con un comando realmente eseguito e non confondere un test unitario con una prova enterprise.

# 1. Inventario generale da verificare

Il branch include:

- AutoMode e orchestrator;
- manual core e chain planner;
- WorldModel e knowledge graph;
- C2 server e C2 shell;
- beacon multipiattaforma;
- HMAC/mTLS e task lease;
- remote session con screen, mouse e tastiera;
- Electron UI;
- AD graph locale ispirato a BloodHound;
- OSINT e account correlation;
- social delivery e phishing workflows;
- web/exploit orchestration;
- post-exploitation e lateral movement;
- cloud, Kubernetes e mobile capability;
- reporting e ATT&CK enrichment;
- evolution author, sandbox, gate, lab, beta e publish;
- learning, experience e LLM advisor;
- test suite e CI.

Stabilire per ogni capability se è:

- `shell_command` operativo;
- `in_process_engine` operativo;
- `marker_only`;
- `lab_only`;
- `simulation`;
- `not_validated`.

Nel codice sono presenti marker adapter intenzionali, ad esempio per alcune capability web/IDOR. Non contarli come capability realmente eseguibili senza verificare il percorso effettivo.

# 2. C2 e beacon

## 2.1 Verifiche funzionali

Analizzare:

- enrollment;
- HMAC;
- mTLS;
- timestamp, nonce e counter;
- rotation e revoke;
- check-in;
- reconnect;
- task queue;
- task lease;
- result acknowledgement;
- deduplication;
- server restart;
- clock skew;
- packet loss;
- duplicate delivery;
- failure del primo check-in;
- stato beacon e stato C2 dopo recovery.

Testare con una matrice che includa network loss, risposta HTTP persa, task ricevuto ma risultato perso, restart del server, rotation durante il task, revoca durante la sessione e due operatori concorrenti.

## 2.2 Punti già emersi da verificare

### Auto-persist al primo check-in

`C2State.update_beacon()` accoda `persist` per un beacon nuovo. Verificare se questo è un requisito intenzionale o un side effect da rimuovere. Se viene mantenuto, deve essere protetto da engagement manifest, capability grant, approval, audit e rollback receipt.

### Beacon non enrolled

Verificare il comportamento quando `beacon_auth_required` è disabilitato. Un listener non-localhost dovrebbe avere un production profile fail-closed, enrollment bootstrap separato e rifiuto degli identity anonimi.

### Nonce in memoria

Verificare replay e restart. Se la history nonce è solo in memoria, definire server epoch, TTL durevole o altro meccanismo che eviti replay dopo restart.

### Task string

Verificare se `queue_task()` e il dispatcher usano stringhe arbitrarie. Il modello preferito è un task tipizzato:

```json
{
  "task_id": "...",
  "capability": "internal_probe",
  "args": {},
  "engagement_id": "...",
  "scope_id": "...",
  "policy_hash": "...",
  "expires_at": "...",
  "nonce": "...",
  "operator_id": "..."
}
```

L’autenticazione del task non deve equivalere automaticamente all’autorizzazione di ogni capability.

### Payload token

Verificare token in query string, token riutilizzabili, logging, reverse proxy e scope per beacon/platform/artifact. Se il token viaggia nell’URL, verificare esposizione in log e process history.

## 2.3 Feature C2 numerose

Concludere chiaramente se ogni problema è:

- un bug;
- un problema di autorizzazione;
- una necessità di separazione dei token;
- un hardening opzionale;
- nessun problema reale.

Non indicare la quantità di feature come finding.

# 3. Remote session con input

Analizzare:

- acquisizione frame;
- compressione;
- sequence number;
- stale frames;
- frame drop;
- mouse move/click/scroll;
- tastiera e key repeat;
- coordinate e scaling;
- focus;
- race polling/input;
- reconnect;
- expiry;
- revoke;
- audit;
- viewer authentication;
- CSRF/CORS/CSP;
- cleanup;
- isolamento per beacon/engagement.

La feature deve conservare il controllo mouse/tastiera. Le capability possono essere separate in:

- `remote.view`;
- `remote.mouse`;
- `remote.keyboard`;
- `remote.clipboard`;
- `remote.file_transfer`;
- `remote.recording`.

La separazione non serve a ridurre la funzionalità, ma a rendere ogni azione autorizzabile e revocabile.

Valutare anche i limiti reali:

- Windows UAC e secure desktop;
- Linux X11 e Wayland;
- macOS TCC e permessi;
- Android input e permission model.

# 4. Manual core e chain planner

Analizzare `phantom/core/chain.py` e tutte le mappature operator-to-capability.

Verificare:

- mapping realmente esistenti;
- capability operative contro marker/stub;
- preview e execution equivalenti;
- target resolution;
- scope snapshot;
- timeout;
- command digest;
- exit code;
- timeout e termination;
- interpretazione dei finding;
- aggiornamento del WorldModel;
- invalidazione delle chain stale;
- gate per pivot e post-exploitation.

Punto specifico: verificare se `execute_step()` può restituire `True` dopo un `run_command()` fallito. Il risultato deve distinguere:

```text
planned
previewed
approved
started
completed
failed
blocked
detected
cancelled
rolled_back
```

La preview e l’esecuzione devono usare lo stesso contesto e policy decision. Un comando o target modificato dopo l’approvazione deve richiedere una nuova approvazione.

# 5. Active Directory e BloodHound

Verificare `phantom/core/ad_graph.py`, ingest e test.

La descrizione corretta da verificare è **AD graph locale ispirato a BloodHound**, non automaticamente integrazione BloodHound completa.

## 5.1 Funzionalità già osservabili

Verificare supporto a:

- domain;
- user;
- group;
- computer;
- DC;
- `member_of`;
- `admin_to`;
- `session`;
- `cracked`;
- `owns`;
- nested groups;
- path BFS;
- ingest `ad_users`;
- ingest `ad_user`;
- ingest `ad_weakness`;
- ingest `ad_creds`;
- ingest domain credentials;
- JSON Electron;
- ASCII tree;
- persistence.

## 5.2 Gap da verificare

- collector SharpHound;
- parser JSON BloodHound moderno;
- Neo4j;
- ACL/ACE;
- GenericAll;
- GenericWrite;
- WriteDACL;
- WriteOwner;
- AddMember;
- ForceChangePassword;
- DCSync;
- GPO;
- delegation;
- trusts;
- forests;
- SID/GUID;
- LAPS/gMSA;
- local admin;
- RDP/WinRM/DCOM/PSRemote;
- session timestamp e logon type;
- freshness e provenance;
- confidence per edge;
- scala oltre poche centinaia di nodi.

Valutare se il JSON riscritto a ogni mutazione e la BFS corrente sono sufficienti per grandi domini enterprise. Proporre schema object/relationship con source, collected_at, confidence, freshness, evidence e identity identifiers.

# 6. AutoMode, reasoning e multi-agent

Separare sempre:

```text
observed_fact
inference
hypothesis
suggestion
decision
effect
result
evidence
learned_knowledge
```

Verificare:

- phase transitions;
- cancellation;
- resume;
- worker lifecycle;
- multi-agent concurrency;
- stale state;
- scope propagation;
- stealth/aggressive profiles;
- LLM advisory role;
- confidence;
- provenance;
- invalidation dei finding;
- retry e backoff;
- budget per agent;
- duplicate actions;
- result merge.

Il modello non deve ampliare lo scope o promuovere automaticamente una capability senza policy. L’LLM deve proporre, non modificare direttamente policy, scope o registry trusted.

# 7. Evolution e self-improvement

Analizzare:

- `loop.py`;
- `author.py`;
- `sandbox.py`;
- `gate.py`;
- `lab.py`;
- `publish.py`;
- `beta.py`;
- `learned/__init__.py`;
- `llm_advisor.py`;
- state persistence;
- branch/PR flow.

Verificare i seguenti punti:

1. state JSON atomico e process-safe;
2. budget reservation prima dello spawn;
3. worker concurrency;
4. crash recovery;
5. commit/base pinning;
6. diff allowlist;
7. GitHub token fuori da URL/process list/log;
8. beta PR con digest e provenance;
9. import learned fuori dal processo principale;
10. gate AST distinto da sandbox reale;
11. filesystem read-only;
12. egress policy;
13. syscall/resource limits;
14. canary;
15. rollback;
16. registry versioning;
17. future-run availability soltanto dopo review/merge.

Il flusso desiderato è:

```text
failure
→ candidate
→ isolated validation
→ lab replay
→ signed artifact
→ branch
→ PR
→ human review
→ merge
→ availability only for future runs
```

# 8. Scope, executor e workflow

Verificare:

- scope vuoto fail-open/fail-closed;
- hostname e A/AAAA resolution;
- DNS rebinding;
- CIDR expansion e limiti;
- redirect target;
- pivot target;
- derived target revalidation;
- identity target vs network target;
- command injection;
- `shell=True`;
- process group kill;
- child cleanup;
- timeout;
- terminal state restoration;
- checkpoint atomicity;
- resume after crash;
- duplicate effects;
- workflow global state;
- WorldModel concurrency;
- history persistence.

Ogni side effect deve essere associato a scope snapshot, target canonicalizzato, policy decision, task ID e risultato verificabile.

# 9. Artifact, secret e report

Verificare:

- password, OTP, cookie, token e private key redaction;
- redazione prima dell’event bus;
- raw/operator report vs client report;
- screenshot, audio, video, GPS e download;
- artifact classification;
- quota;
- encryption at rest;
- TTL;
- cleanup;
- cross-engagement isolation;
- access/read/delete audit;
- HTML escaping;
- JSON export;
- report provenance.

La redazione soltanto nella UI non è sufficiente se il dato raw è già stato persistito nei log, audit, history, WorldModel o report temporanei.

# 10. Electron e UI

Verificare:

- IPC generic request;
- preload surface;
- context isolation;
- node integration;
- CSP;
- navigation policy;
- window-open policy;
- endpoint allowlist;
- schema validation;
- auth context;
- polling overlap;
- AbortController;
- reconnect;
- terminal states;
- viewer auth;
- artifact isolation;
- stale UI state.

L’IPC deve esporre API typed e specifiche, non una superficie generica che inoltra metodo, endpoint e body arbitrari.

# 11. OSINT, account correlation, phishing e social engineering

Questa sezione deve essere interpretata nel contesto di engagement autorizzati, simulazioni concordate, red-team con scope scritto e test su identità o account di laboratorio. L’obiettivo tecnico della review non è rimuovere OSINT, phishing o social engineering, ma verificare che siano **riproducibili, tracciabili, evidence-based e limitati agli asset autorizzati**.

## 11.1 Account correlation quando il profilo è privato

Il requisito funzionale dichiarato è il seguente: se un profilo è privato, Phantom deve poter cercare **account pubblici potenzialmente collegati alla stessa persona** e costruire una correlazione a partire da segnali pubblici, come username riutilizzati, alias, avatar pubblici, bio, domini, email pubblicate, commenti pubblici, tag pubblici, follower/following visibili, repository, forum e altri profili accessibili senza autenticazione speciale.

Questa funzione va chiamata **public-account correlation** o **reverse account correlation**, non reverse engineering del profilo privato. La review deve verificare che il sistema:

- non tenti di accedere a contenuti privati;
- non aggiri privacy controls, login, MFA o access-control;
- non usi account falsi o interazioni ingannevoli fuori da un piano autorizzato;
- non tratti un omonimo come la stessa persona;
- non trasformi tag, commenti o follower in identità certa senza segnali indipendenti;
- conservi soltanto evidenze pubblicamente accessibili e proporzionate allo scope;
- registri timestamp, URL, provider, metodo di raccolta e stato di disponibilità;
- gestisca correttamente contenuti cancellati, modificati o non più verificabili.

Il motore dovrebbe produrre candidati, non una certezza automatica:

```text
private_profile_reference
  → public candidate accounts
  → independent public signals
  → contradictions and alternative identities
  → confidence score
  → operator verification
  → approved target/persona record
```

Ogni candidate identity dovrebbe avere:

| Campo | Scopo |
|---|---|
| `candidate_id` | Identificatore interno non ambiguo |
| `platform` | Origine del profilo |
| `public_url` | URL pubblico osservato |
| `observed_at` | Momento della raccolta |
| `signals` | Alias, bio, avatar, dominio, repo, cross-link |
| `independent_sources` | Numero e tipo di fonti indipendenti |
| `contradictions` | Elementi che smentiscono il collegamento |
| `confidence` | Weak, plausible, strong o operator-verified |
| `scope_ref` | Engagement e motivo autorizzativo |
| `review_status` | Unreviewed, reviewed, rejected, approved |

Il sistema non deve usare un candidate `weak` o `plausible` come destinatario automatico di phishing, DM, tracking o delivery. L’operatore deve poter approvare, rifiutare o fondere candidati, mantenendo l’evidenza storica.

## 11.2 Account linking e reverse correlation

Verificare collisioni di username, alias, omonimi, avatar riutilizzati, domini, email pubbliche, repository, bio, link esterni, commenti, tag e relazioni visibili. Ogni segnale deve avere un peso documentato e non deve essere contato più volte quando deriva dalla stessa fonte.

Il motore dovrebbe distinguere:

```text
same-string match
  ≠ same-account evidence
  ≠ same-person hypothesis
  ≠ verified identity
```

Servono inoltre:

- deduplicazione delle fonti;
- timestamp e freshness;
- gestione delle contraddizioni;
- confidence calibration su casi positivi e negativi;
- dataset di omonimi e account decoy;
- protezione contro confirmation bias del LLM;
- provenance completa per ogni edge del grafo;
- possibilità di cancellare o invalidare una correlazione senza cancellare l’audit della decisione.

## 11.3 Phishing e social engineering autorizzati

La review deve verificare se le capability di phishing e social engineering supportano campagne di simulazione autorizzate, non soltanto la costruzione del messaggio o l’invio.

Le proprietà da verificare sono:

- import di destinatari soltanto da scope approvato;
- engagement manifest con dominio, gruppo, periodo e canali consentiti;
- template versionati e approvati;
- preview del messaggio e del dominio di landing;
- separazione tra simulazione, training e raccolta dati reali;
- rate limit, scheduling e kill switch;
- esclusione di destinatari fuori scope;
- tracciamento di delivery, open, click e report;
- minimizzazione dei dati raccolti;
- nessuna persistenza di password, OTP, cookie o token reali;
- cleanup di landing page, redirect e artifact;
- report aggregato senza esporre dati individuali non necessari;
- audit di chi ha approvato campagna, template e destinatari.

Un ambiente professionale dovrebbe modellare la campagna come oggetto esplicito:

```json
{
  "campaign_id": "...",
  "engagement_id": "...",
  "approved_domains": ["training.example"],
  "approved_recipient_group": "...",
  "channels": ["email"],
  "template_digest": "...",
  "landing_mode": "training-only",
  "collect_real_credentials": false,
  "start_at": "...",
  "expires_at": "...",
  "kill_switch": "...",
  "approver": "..."
}
```

La review deve verificare che una campagna non possa cambiare destinatari, dominio, template o landing dopo l’approvazione senza invalidare l’approvazione e richiederne una nuova.

## 11.4 Social workflows e DM

Per DM, commenti o interazioni social, verificare:

- account e canale esplicitamente autorizzati;
- template e persona approvati;
- limiti di frequenza;
- gestione dei provider failure e rate limit;
- audit di ogni interazione;
- opt-out e stop immediato;
- distinzione tra osservazione pubblica e interazione attiva;
- divieto di estendere automaticamente la campagna a follower, amici o tag non presenti nello scope;
- report che separi messaggio preparato, messaggio inviato, consegna e risposta.

Il sistema deve evitare che una relazione osservata — per esempio un tag o un commento — venga convertita automaticamente in un nuovo target. Deve produrre un candidato con motivazione, evidenze e richiesta di approvazione.

## 11.5 Test OSINT/social richiesti

La review deve proporre test su:

| Scenario | Risultato atteso |
|---|---|
| Username uguale di due persone diverse | Confidence bassa e nessun auto-targeting |
| Profilo privato con alias pubblico | Candidate account, non accesso al profilo privato |
| Avatar riutilizzato da account decoy | Contraddizione o confidence ridotta |
| Commento/tag pubblico | Evidenza timestampata, non identità certa |
| Account cancellato | Record stale e marcato non verificabile |
| Provider rate-limited | Backoff, stato partial e nessun retry aggressivo |
| Destinatario fuori scope | Blocco prima della delivery |
| Template modificato dopo approval | Approval invalidata |
| Kill switch campagna | Stop di scheduling, queue e landing |
| Credential/OTP canary | Mai persistito in log, audit, artifact o report |

La conclusione deve separare chiaramente account correlation pubblica, phishing simulation e social engineering attivo. Tutte possono essere feature valide in un engagement autorizzato, ma devono avere scope, approvazione, provenance, limiti e cleanup distinti.

# 12. Cloud, Kubernetes e mobile

Verificare se le capability sono realmente operative oppure soltanto generatori/adapters:

- AWS roles, policies, SCP e permission boundaries;
- Azure subscriptions, management groups, Entra roles e Conditional Access;
- GCP IAM e service accounts;
- cross-account trust;
- workload/managed identity;
- Kubernetes service accounts, RBAC e escape paths;
- MDM/mobile fingerprint;
- Android permissions;
- artifact e credential handling.

Ogni credential/identity deve avere provider, scope, expiration, source, confidence, permission snapshot e revocation status.

# 13. Web ed exploit automation

Classificare ogni capability come command, engine, stub, lab o non validata. Verificare contro fixture moderne:

- reverse proxy;
- WAF;
- API gateway;
- OAuth/OIDC;
- GraphQL;
- JSON API;
- CSRF;
- rate limiting;
- multi-tenant authorization;
- signed URLs;
- SSRF egress restriction;
- modern upload pipeline.

Non basta che venga costruita una stringa SQLi, SSRF, upload, traversal, IDOR o RCE. Servono prove di esecuzione, interpretazione, false positive, timeout e cleanup in un lab autorizzato.

# 14. Enterprise readiness

Creare una matrice con:

| Scenario | Codice presente | Lab | Integration test | Validazione runtime | Gap |
|---|---|---|---|---|---|
| Windows 11 |  |  |  |  |  |
| Defender/EDR lab |  |  |  |  |  |
| Linux systemd |  |  |  |  |  |
| macOS permissions |  |  |  |  |  |
| AD nested groups |  |  |  |  |  |
| AD ACL/delegation |  |  |  |  |  |
| Entra ID |  |  |  |  |  |
| AWS/Azure/GCP |  |  |  |  |  |
| Kubernetes |  |  |  |  |  |
| NAT/proxy/TLS inspection |  |  |  |  |  |
| IPv4/IPv6 |  |  |  |  |  |
| WAF/API gateway |  |  |  |  |  |
| Network segmentation |  |  |  |  |  |
| Packet loss/clock skew |  |  |  |  |  |
| Remote desktop input |  |  |  |  |  |
| Evolution replay |  |  |  |  |  |

La prova su Metasploitable2 deve essere considerata regression history, non prova di compatibilità enterprise moderna.

# 15. Test e riproducibilità

Verificare che una nuova macchina possa:

1. installare dipendenze pinned;
2. eseguire compile/typecheck;
3. raccogliere tutti i test;
4. eseguire test unitari;
5. eseguire test integration;
6. avviare lab Docker;
7. compilare beacon target;
8. esportare artifact e report;
9. pulire completamente i dati temporanei.

Il precedente tentativo di raccolta mirata ha individuato 19 test ma si è fermato per:

```text
ModuleNotFoundError: No module named 'rich'
```

È comparso anche un warning per `asyncio_mode` senza plugin disponibile. Verificare `requirements`, lockfile, bootstrap CI e dipendenze C/C++/Android.

Test negativi prioritari:

- beacon non enrolled rifiutato su listener non-localhost;
- auto-persist non accodata senza grant;
- task string non autorizzata rifiutata;
- replay dopo restart gestito;
- remote input senza session token rifiutato;
- remote expiry revoca input e stream;
- artifact cross-engagement isolati;
- evolution budget atomico;
- beta capability con digest diverso rifiutata;
- learned module con primitive non consentite bloccato a runtime;
- execute step con exit code non-zero marcato failed;
- preview digest diverso dall’execution rifiutato;
- secret canary assente da event bus, audit, artifact, report e PR.

# 16. Roadmap richiesta

## P0 — Correttezza e confini

- distinguere avvio, successo, failure, detection, cleanup e rollback;
- correggere lo stato di `execute_step()`;
- introdurre task typed e capability grants;
- rendere scope snapshot e target resolution immutabili per step;
- rendere fail-closed l’enrollment production;
- togliere o proteggere l’auto-persist;
- separare remote session da task channel;
- introdurre session token, expiry e revoke;
- impedire secret persistence;
- rendere la suite installabile ed eseguibile.

## P1 — Architettura enterprise

- AD graph ricco con ACL, delegation, trusts, SID/GUID e freshness;
- parser/adapter BloodHound esplicito, se desiderato;
- identity graph cloud/on-prem;
- C2 resilience harness;
- artifact classification e retention;
- Electron IPC typed;
- process/container isolation per learned capability;
- evolution state transazionale;
- PR diff allowlist e token handling sicuro;
- canary e rollback.

## P2 — Validazione realistica

- lab Windows/AD/EDR;
- AD hardened e hybrid identity;
- Linux/macOS/Android;
- AWS/Azure/GCP/Kubernetes;
- proxy, NAT, segmentation, TLS inspection;
- WAF/API/OIDC;
- remote session input stress test;
- packet loss, restart, clock skew;
- benchmark di false positive, false negative, detection, cleanup e time-to-evidence.

# 17. Domande aperte

1. Phantom è single-operator/local-only o deve supportare più operatori e engagement?
2. L’auto-persist al primo check-in è requisito o comportamento temporaneo?
3. Remote session deve avere indicator locale obbligatorio in quale profilo?
4. Il manual core deve poter eseguire pivot e post-exploitation senza un approval manifest separato?
5. Il BloodHound graph deve importare file SharpHound reali oppure restare un graph Phantom nativo?
6. Quali dati possono essere inviati a un LLM remoto?
7. Qual è la retention per screenshot, recording, audio, GPS e download?
8. Qual è il formato dell’engagement manifest?
9. Quali capability sono lab-only, authorized-engagement e research-only?
10. Il token GitHub è PAT fine-grained o GitHub App token?
11. Quali piattaforme beacon devono essere release-grade?
12. Qual è la definizione misurabile di “non rilevato” nel test beacon?

# 18. Criteri di giudizio finale

Il revisore deve produrre una conclusione separata su:

- qualità del codice;
- completezza funzionale;
- affidabilità runtime;
- compatibilità enterprise;
- sicurezza dei confini;
- maturità AutoMode;
- maturità manual core;
- maturità AD/BloodHound;
- maturità C2/beacon;
- maturità remote session;
- maturità evolution engine.

Il giudizio non deve essere binario. La conclusione desiderata deve indicare cosa è già forte, cosa è promettente, cosa è incompleto, cosa è soltanto non verificato e quali test cambierebbero la valutazione.

La tesi da verificare è:

> Phantom non è semplicemente un wrapper di tool legacy. È un sistema ambizioso che prova a integrare orchestrazione, reasoning, manual control, C2, remote interaction, AD graph, Electron e self-improvement. La questione non è quante feature possieda, ma se ogni feature abbia un contratto corretto, evidenza runtime, failure handling, cleanup, scope enforcement e test realistici.
