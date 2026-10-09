# Phantom — AutoMode, Tool Discovery e Enterprise Readiness
## Brief tecnico completo per analisi e sviluppo con DeepSeek / Freebuff

**Data:** 5 ottobre 2026  
**Repository:** `Terminalkid09/Phantom`  
**Branch di riferimento:** `dev`  
**Obiettivo:** valutare criticamente l’AutoMode, progettare una gestione robusta di tool nuovi senza catalogo fisso e definire una roadmap di miglioramento verificabile.

---

## 1. Contesto

Phantom è una piattaforma di security automation con componenti di:

- AutoMode e planner autonomo;
- WorldModel con findings tipizzati;
- confidence e revisioni delle credenze;
- hypothesis planning;
- failure tracking e cycle detection;
- opsec/noise accounting;
- swarm multi-agent;
- tool selection e fallback;
- external intelligence e phone intelligence;
- identity/OSINT graph;
- AD/BloodHound integration;
- C2 e beacon;
- remote session con frame stream e input interattivo;
- Electron UI;
- learning/evolution module;
- experience memory;
- runtime tool drivers;
- branch/PR workflow per l’evoluzione del sistema.

Il progetto non è più una semplice raccolta di script sequenziali. Ha una struttura da piattaforma agentica avanzata, ma deve ancora dimostrare sufficiente robustezza per essere definito un red-team automation platform enterprise-grade.

Questo documento raccoglie:

1. valutazione realistica dell’AutoMode;
2. fattibilità della gestione dinamica di nuovi tool;
3. limiti attuali del runtime driver system;
4. architettura raccomandata per tool discovery e capability approval;
5. dubbi tecnici da verificare con DeepSeek;
6. roadmap prioritaria;
7. criteri di accettazione e test suggeriti.

> Tutte le funzionalità devono rimanere vincolate a engagement autorizzati, scope esplicito, audit trail e policy di sicurezza. L’obiettivo di questo documento è migliorare affidabilità, controllo e qualità dell’orchestrazione, non rimuovere i controlli di autorizzazione.

---

# 2. Valutazione sintetica

## 2.1 Giudizio generale

La valutazione più onesta è:

> **L’AutoMode è di buon livello architetturale per un progetto personale avanzato, ma non è ancora un red teamer autonomo di livello enterprise.**

Non è un progetto scarso. La base è ambiziosa e superiore alla maggior parte dei tool personali perché prova a modellare in modo esplicito:

- stato del mondo;
- evidenza;
- confidenza;
- ipotesi;
- fallimenti;
- cicli ripetuti;
- rumore operativo;
- costo e rischio delle azioni;
- capability effects;
- scelta degli strumenti;
- apprendimento;
- provenienza delle informazioni;
- scope.

Il punto critico non è il numero di moduli disponibili, ma la qualità dell’intero ciclo decisionale:

```text
osserva
  ↓
interpreta
  ↓
formula ipotesi
  ↓
seleziona capability
  ↓
esegue
  ↓
verifica il risultato
  ↓
aggiorna il WorldModel
  ↓
modifica il piano
  ↓
evita di ripetere errori
```

Questo ciclo esiste già in Phantom, ma alcuni anelli sono più solidi concettualmente che nell’implementazione reale.

## 2.2 Valutazione qualitativa

| Area | Valutazione attuale |
|---|---:|
| Architettura concettuale | **8/10** |
| Modellazione di findings e stato | **7,5/10** |
| Orchestrazione capability | **7/10** |
| Failure handling | **6,5/10** |
| Swarm multi-agent | **6,5/10** |
| Tool discovery | **6/10** |
| Verifica dei risultati | **6/10** |
| Determinismo | **5,5/10** |
| Isolamento plugin/driver | **5/10** |
| Enterprise readiness attuale | **5,5–6/10** |

Questa non è una bocciatura. Significa che la struttura è abbastanza buona da giustificare ulteriori investimenti, ma non abbastanza solida da permettere autonomia illimitata senza supervisione e senza execution gate.

---

# 3. Gestione di tool nuovi senza catalogo fisso

## 3.1 È fattibile?

Sì, è assolutamente fattibile.

Phantom ha già iniziato a muoversi in questa direzione con i **runtime tool drivers**. Un tool può essere descritto da un manifest che dichiara:

- identificativo;
- binario;
- categoria;
- command template;
- input richiesti;
- effects;
- marker di output;
- confidence;
- timeout;
- opsec cost;
- detection risk;
- stealth level;
- prerequisiti.

Questo permette di aggiungere nuovi tool senza modificare necessariamente il catalogo Python principale.

### Esempio di driver dichiarativo

```json
{
  "id": "my_scanner",
  "tool": "my-scanner",
  "category": "recon",
  "description": "Scansione autorizzata di servizi",
  "command": "my-scanner --target {target} --json",
  "effects": ["service", "hostname"],
  "markers": [
    {
      "prefix": "SERVICE:",
      "kind": "service",
      "key": "tcp:{port}",
      "fields": ["port", "name", "version"],
      "confidence": 0.8
    }
  ],
  "requires": ["target"],
  "opsec_cost": 0.2,
  "detection_risk": 0.05,
  "stealth_level": "passive",
  "timeout": 60
}
```

Questa soluzione è utile perché consente di:

- evitare una release per ogni nuovo tool;
- dichiarare input e output in modo uniforme;
- integrare il tool nel planner;
- dichiarare gli effetti sul WorldModel;
- creare fallback tra tool diversi;
- mantenere separata la logica di orchestrazione dalla logica del singolo tool.

## 3.2 Limite dell’implementazione attuale

La gestione attuale è più vicina a un **tool discovery configurabile** che a un agente capace di comprendere autonomamente qualunque nuovo tool.

Attualmente il sistema deve ricevere dal developer/operator:

- command template;
- placeholder corretti;
- effetti dichiarati;
- marker di output;
- parser implicito;
- confidence;
- prerequisiti;
- categoria;
- tool da invocare.

Quindi il sistema sa orchestrare un tool descritto correttamente, ma non necessariamente sa capire da solo:

```text
quali argomenti siano realmente validi;
quale output sia affidabile;
quale riga rappresenti un finding confermato;
quale risultato sia soltanto un banner ambiguo;
quali effetti siano realmente prodotti;
quali errori siano recuperabili;
quale rumore operativo generi il tool.
```

La distinzione fondamentale è:

```text
saper usare una capability descritta
≠
capire autonomamente un tool nuovo
```

---

# 4. Evoluzione in tre livelli

## 4.1 Livello 1 — Driver dichiarativi

Il primo livello è quello già parzialmente presente.

Un manifest descrive il tool e il sistema lo registra come capability.

### Vantaggi

- semplice da implementare;
- facilmente versionabile;
- adatto a tool interni o operator-owned;
- facilmente testabile;
- non richiede modifiche al catalogo statico.

### Limiti

- il manifest può essere errato;
- gli effects possono essere dichiarati in modo eccessivo;
- i marker possono generare falsi finding;
- il command template può introdurre problemi di quoting;
- un file trovato in una directory configurata può diventare eseguibile troppo facilmente;
- il sistema non distingue automaticamente conoscenza appresa e codice eseguibile.

## 4.2 Livello 2 — Adapter con schema tipizzato

Il modello più robusto dovrebbe separare chiaramente:

```text
Tool Manifest
    ↓
Input Schema
    ↓
Command Builder
    ↓
Execution Policy
    ↓
Output Parser
    ↓
Typed Findings
```

### Esempio concettuale

```json
{
  "id": "http_probe",
  "binary": "httpx",
  "version": ">=1.4",
  "category": "recon",
  "input_schema": {
    "target": "hostname_or_url",
    "ports": "optional_port_list"
  },
  "execution": {
    "mode": "argv",
    "argv": [
      "httpx",
      "-json",
      "-u",
      "{target}"
    ]
  },
  "output_schema": {
    "format": "jsonl",
    "fields": {
      "url": "string",
      "status_code": "integer",
      "technologies": "string[]"
    }
  },
  "effects": [
    "web_app",
    "technology",
    "http_status"
  ]
}
```

Il comando dovrebbe essere costruito come array argv:

```python
[
    "httpx",
    "-json",
    "-u",
    "https://target.example"
]
```

Non come stringa shell:

```python
"httpx -json -u https://target.example"
```

### Vantaggi

- quoting più sicuro;
- validazione forte degli input;
- nessuna shell obbligatoria;
- timeout e cancellazione più prevedibili;
- parsing strutturato;
- test offline più semplici;
- possibilità di eseguire fake tool nei test;
- minore rischio di command injection accidentale.

La modalità `shell=True` dovrebbe restare disponibile solo per capability esplicitamente classificate come pipeline e sottoposte a policy aggiuntiva.

## 4.3 Livello 3 — Capability discovery assistita

Il terzo livello permette a Phantom di proporre automaticamente un driver per un tool nuovo.

Possibile flusso:

```text
phantom tool import ./my-tool
       ↓
verifica hash e provenienza
       ↓
esegue solo --help / -h / version
       ↓
raccoglie informazioni compatibilità
       ↓
propone input e output schema
       ↓
crea un manifest candidato
       ↓
crea fixture e test iniziali
       ↓
lascia la capability disabilitata
       ↓
attende approvazione
```

Il flusso non dovrebbe essere:

```text
file trovato nella directory
       ↓
esecuzione automatica
```

---

# 5. Stato corretto di una capability dinamica

Una capability nuova dovrebbe attraversare stati espliciti:

```text
discovered
    ↓
candidate
    ↓
reviewed
    ↓
approved
    ↓
enabled
    ↓
executed
    ↓
validated
```

## 5.1 Significato degli stati

### `discovered`

Il sistema ha trovato un binario, un manifest o un plugin.

Non può ancora essere eseguito automaticamente.

### `candidate`

È stata generata una proposta con:

- command schema;
- input schema;
- output schema;
- effetti ipotizzati;
- rischi;
- dipendenze;
- test iniziali.

### `reviewed`

La proposta è stata analizzata da un operatore o da una pipeline di verifica.

### `approved`

L’operatore ha accettato il manifest per un determinato engagement o ambiente.

### `enabled`

La capability può essere scelta dal planner.

### `executed`

La capability è stata effettivamente invocata.

### `validated`

L’output ha prodotto evidenza sufficiente a confermare o rifiutare gli effetti dichiarati.

---

# 6. Provenienza e supply chain dei tool

Ogni tool dovrebbe avere metadati come:

```json
{
  "tool_id": "my_scanner",
  "version": "1.2.3",
  "path": "/opt/tools/my_scanner",
  "sha256": "...",
  "source": "operator-local",
  "discovered_at": "2026-10-05T...",
  "approved_by": "operator",
  "approved_at": "2026-10-05T...",
  "supported_platforms": ["linux", "windows"],
  "required_privileges": "user",
  "status": "approved"
}
```

Se il binario cambia hash, Phantom dovrebbe:

1. segnalare la modifica;
2. invalidare l’approvazione precedente;
3. sospendere l’esecuzione automatica;
4. richiedere nuova verifica;
5. preservare nel report quale versione era stata usata.

## 6.1 Compatibilità da dichiarare

Un driver robusto dovrebbe specificare:

- sistemi operativi supportati;
- architetture supportate;
- versione minima;
- dipendenze;
- privilegi richiesti;
- supporto IPv4/IPv6;
- supporto proxy;
- supporto offline;
- formato di output;
- comportamento su timeout;
- comportamento su target irraggiungibile;
- costi o rate limit del provider;
- eventuale accesso a dati sensibili.

---

# 7. Effetti e finding: non fidarsi solo della dichiarazione

Non basta dichiarare:

```json
"effects": ["service"]
```

Bisogna definire quale evidenza prova quell’effetto.

## 7.1 Distinzione raccomandata

Per una porta o servizio web, distinguere almeno:

```text
port_open
service_detected
product_detected
version_observed
version_confirmed
vulnerability_candidate
vulnerability_confirmed
```

Non devono essere trattati come equivalenti.

## 7.2 Finding con evidenza ricca

```json
{
  "kind": "service",
  "key": "tcp:443",
  "value": {
    "name": "https",
    "product": "nginx",
    "version": "1.24"
  },
  "confidence": 0.82,
  "source": "http_probe",
  "evidence": "Server: nginx/1.24",
  "evidence_quality": 0.78,
  "source_reliability": 0.90,
  "freshness": 0.98,
  "independent_sources": 2,
  "observed_at": "2026-10-05T...",
  "ttl": 3600,
  "target": "target.example"
}
```

---

# 8. Modello di confidence da migliorare

Il solo valore:

```text
confidence = 0.8
```

è troppo semplice per sostenere un AutoMode enterprise.

Sarebbe meglio separare:

```text
confidence
source_reliability
evidence_quality
freshness
independence
impact
provenance
```

## 8.1 Esempio

```json
{
  "confidence": 0.82,
  "source_reliability": 0.90,
  "evidence_quality": 0.75,
  "freshness": 0.98,
  "independent_sources": 2
}
```

Un dato ottenuto da provider esterno e un dato verificato direttamente con una capability locale non dovrebbero essere trattati allo stesso modo anche se hanno lo stesso valore di `confidence`.

## 8.2 Possibile scoring

```text
belief_score =
    confidence
  × source_reliability
  × evidence_quality
  × freshness
  × independence_bonus
```

Questo punteggio non dovrebbe sostituire completamente i valori originali. Deve servire a ordinare o confrontare i finding mantenendo comunque la loro provenienza.

---

# 9. Problema del first-writer-wins nello swarm

È stato riprodotto un comportamento importante nel board swarm:

```text
finding external-intel: confidence 0.50
finding scan diretto: confidence 0.95
```

Il secondo finding può non sostituire il primo se il board usa `first-writer-wins`.

## 9.1 Perché è un problema

Il primo risultato disponibile non è necessariamente il risultato più affidabile.

L’ordine può dipendere da:

- scheduling;
- latenza di rete;
- carico del worker;
- provider esterno;
- durata della scansione;
- ordine di avvio dei sub-agent.

Quindi due run identici possono produrre belief differenti solo per effetto dell’ordine di completamento.

## 9.2 Dove first-writer-wins è appropriato

È adatto a:

- lock;
- assegnazione task;
- ownership temporanea;
- idempotency key;
- reservation di una risorsa.

Non dovrebbe decidere da solo quale finding rappresenta la realtà.

## 9.3 Merge consigliato

Conservare tutti i contributi e calcolare il belief corrente in base a:

```text
confidence
source_reliability
evidence_quality
freshness
independence
specificity
```

Schema concettuale:

```python
belief = merge_findings(
    kind="service",
    key="tcp/443",
    candidates=[finding_a, finding_b, finding_c],
)
```

Il sistema dovrebbe mantenere:

- current belief;
- alternative beliefs;
- rejected evidence;
- revision history;
- reason della scelta;
- timestamp;
- source ranking.

---

# 10. Dubbi principali sull’AutoMode

## 10.1 Il planner sceglie, ma verifica sempre?

Un agente enterprise non dovrebbe considerare sufficiente:

```text
exit code 0
```

Dovrebbe chiedersi:

```text
Ho ottenuto una prova verificabile dell’effetto?
Il risultato è coerente con altre osservazioni?
Il dato è fresco?
Il parser ha interpretato correttamente l’output?
Il tool ha generato un falso positivo?
Il risultato è osservato o solo dedotto?
```

## 10.2 Il planner distingue bene i livelli di evidenza?

Devono essere distinti almeno:

```text
port_open
service_detected
product_detected
version_confirmed
vulnerability_candidate
vulnerability_confirmed
credential_candidate
credential_validated
identity_candidate
identity_confirmed
```

Senza questa distinzione il planner può prendere decisioni sintatticamente corrette, ma operativamente sbagliate.

## 10.3 Il reasoning LLM è sufficientemente vincolato?

L’LLM può essere utile per:

- spiegare findings;
- proporre ipotesi;
- suggerire tool;
- classificare output non strutturato;
- confrontare risultati;
- individuare contraddizioni;
- proporre un nuovo driver;
- creare test fixture;
- suggerire una remediation.

Non dovrebbe poter decidere da solo:

- che un finding è confermato senza evidenza;
- che un driver è automaticamente trusted;
- che una capability ad alto impatto è approvata;
- di uscire dallo scope;
- di superare una policy;
- di modificare direttamente il runtime principale.

La struttura raccomandata è:

```text
LLM proposes
    ↓
deterministic policy checks
    ↓
typed planner validation
    ↓
execution gate
    ↓
evidence interpreter
    ↓
WorldModel update
```

Non:

```text
LLM decides
    ↓
shell command
```

## 10.4 L’AutoMode è forte nell’orchestrazione, ma meno nella comprensione universale

Phantom è già in grado di orchestrare capability descritte.

La parte ancora da sviluppare è la comprensione semantica generale di tool e output nuovi.

Per esempio, il sistema può utilizzare bene un tool se gli vengono forniti:

- command template;
- input;
- effects;
- marker parser;
- preconditions.

Ma non garantisce ancora di capire automaticamente che:

```text
questa riga è una conferma forte;
questa risposta è un banner ambiguo;
questo output è parziale;
questo finding è stale;
questo provider ha restituito un risultato non verificabile;
questo effetto dichiarato non è stato realmente raggiunto.
```

---

# 11. Cosa dovrebbe significare “AutoMode enterprise”

## 11.1 Determinismo

A parità di:

- target;
- scope;
- tool disponibili;
- configurazione;
- stato iniziale;
- provider;

il sistema dovrebbe produrre una sequenza simile oppure spiegare perché è divergente.

La casualità del comportamento deve essere distinguibile da:

- nuova evidenza;
- scheduling;
- LLM sampling;
- provider failure;
- race condition.

## 11.2 Auditabilità

Ogni decisione importante dovrebbe registrare:

```text
goal
belief usati
hypotheses attive
capability candidate
capability scelta
capability scartate
motivi di esclusione
costo
rischio
scope decision
policy decision
evidence ottenuta
risultato
motivo del prossimo passo
```

## 11.3 Reversibilità

Ogni azione dovrebbe avere, dove possibile:

```text
rollback
expiry
kill condition
cleanup
resource owner
```

## 11.4 Incertezza esplicita

L’agente dovrebbe produrre output come:

```text
Non ho confermato X.
Ho solo un’ipotesi con evidenza Y.
La prossima verifica meno rumorosa è Z.
Il dato scade tra N minuti.
```

## 11.5 Capacità di fermarsi

Un agente professionale non è quello che continua più a lungo.

È quello che sa fermarsi quando:

- non esiste una strada economicamente sensata;
- il rumore supera il budget;
- l’evidenza è insufficiente;
- il target è ambiguo;
- la capability non è trusted;
- l’azione è fuori scope;
- esiste un rischio operativo non previsto;
- il risultato è già sufficientemente dimostrato.

---

# 12. Aree mancanti o da rafforzare

## 12.1 Evidence-driven planner

Ogni azione deve:

1. partire da un finding o hypothesis esplicita;
2. avere una ragione misurabile;
3. dichiarare il risultato atteso;
4. terminare con una verifica dell’effetto;
5. aggiornare il WorldModel solo con evidenza sufficiente;
6. registrare perché il passo successivo è stato scelto.

## 12.2 Capability trust system

Separare completamente:

```text
scoperto
→ proposto
→ revisionato
→ approvato
→ abilitato
→ eseguito
→ validato
```

## 12.3 Belief merge corretto

Sostituire la logica first-writer-wins per i findings con un merge basato su:

```text
evidence quality
source reliability
freshness
confidence
independence
specificity
```

## 12.4 Provenance completa

Ogni finding dovrebbe sapere:

- quale capability lo ha prodotto;
- quale versione del tool;
- quale hash del binario;
- quale comando o argv è stato usato;
- quale output lo prova;
- quando è stato osservato;
- quale trasformazione ha subito;
- quale parser lo ha interpretato;
- se è stato corroborato da una fonte indipendente.

## 12.5 Failure handling tipizzato

Separare chiaramente:

```text
tool_missing
tool_crashed
timeout
network_unreachable
auth_failed
scope_denied
policy_denied
parse_failed
partial_result
stale_result
contradictory_result
operator_cancelled
```

Un generico `False` o `exit code != 0` non è sufficiente per un planner autonomo.

## 12.6 Contratti tra UI e backend

Ogni endpoint usato da Electron dovrebbe essere verificato automaticamente contro:

- allowlist IPC;
- route backend;
- metodo HTTP;
- payload schema;
- status code attesi;
- risposta typed;
- gestione errori.

Il branch ha già mostrato failure di drift tra endpoint UI, allowlist e route reali. Questo deve diventare un gate CI.

## 12.7 Cancellation e task lifecycle

Per ogni task servono:

- task ID;
- idempotency key;
- lease;
- timeout;
- cancellation token;
- process group;
- cleanup;
- risultato parziale;
- retry policy;
- stato terminale.

---

# 13. Architettura proposta per nuovi tool

## 13.1 Componenti

```text
Tool Registry
    ↓
Tool Provenance Store
    ↓
Manifest Validator
    ↓
Approval Policy
    ↓
Typed Command Builder
    ↓
Execution Broker
    ↓
Output Normalizer
    ↓
Evidence Validator
    ↓
Finding Merger
    ↓
WorldModel
```

## 13.2 Tool Registry

Responsabilità:

- individuare tool installati;
- risolvere versione;
- verificare path;
- calcolare hash;
- associare platform/architecture;
- tenere lo stato di approvazione;
- impedire collisioni di ID;
- sospendere tool cambiati.

## 13.3 Manifest Validator

Deve verificare:

- schema JSON;
- ID valido;
- categoria valida;
- input dichiarati;
- placeholder conosciuti;
- effects ammessi;
- timeout bounded;
- detection risk in range;
- command mode;
- output format;
- parser coerente con schema.

## 13.4 Approval Policy

Esempio:

```text
passive + argv + read-only + no external provider
    → auto-approve opzionale in lab

network active + shell pipeline
    → approvazione operatore

state-changing / high-risk
    → approvazione esplicita per run

unknown driver / learned driver
    → disabilitato fino a review e test
```

## 13.5 Execution Broker

Il broker dovrebbe centralizzare:

- scope check;
- policy check;
- tool availability;
- input validation;
- argv construction;
- timeout;
- process group;
- cancellation;
- output capture;
- redaction;
- audit event.

Nessun adapter dovrebbe poter bypassare il broker.

---

# 14. Learning ed evolution

Il modello branch/PR è una buona direzione. È molto meglio far proporre modifiche su un branch separato rispetto a modificare direttamente il branch `dev`.

## 14.1 Cosa può imparare automaticamente

È ragionevole permettere al sistema di imparare:

- quali tool sono disponibili;
- quali errori sono ricorrenti;
- quali capability hanno successo in determinate condizioni;
- quali provider sono affidabili;
- quali parser producono falsi positivi;
- quali fallback sono più efficienti;
- quali azioni sono rumorose;
- quali precondizioni mancano spesso.

## 14.2 Cosa non dovrebbe modificare automaticamente senza review

- policy di scope;
- auth middleware;
- token handling;
- capability ad alto impatto;
- code path C2;
- parser che possono confermare vulnerabilità;
- command template shell;
- regole di execution gate;
- confini di sandbox;
- allowlist dei tool.

## 14.3 Modello consigliato

```text
run
  ↓
experience record
  ↓
failure pattern
  ↓
proposal
  ↓
replay fixture
  ↓
unit/integration/security tests
  ↓
branch dedicato
  ↓
PR
  ↓
review umano
  ↓
merge
  ↓
release controllata
```

L’LLM può aiutare a creare una proposta, ma la promozione deve dipendere da test deterministici e policy.

---

# 15. Test raccomandati

## 15.1 Tool discovery

```text
test_discovered_driver_is_not_executable_by_default
test_manifest_requires_valid_schema
test_manifest_rejects_unknown_placeholder
test_driver_binary_hash_is_recorded
test_changed_binary_invalidates_approval
test_driver_requires_operator_approval
test_argv_driver_does_not_use_shell
test_shell_pipeline_requires_explicit_policy
test_invalid_input_is_rejected_before_execution
test_missing_tool_returns_typed_error
```

## 15.2 Output ed evidenza

```text
test_marker_without_required_fields_is_not_a_finding
test_low_quality_banner_is_not_version_confirmation
test_partial_output_is_marked_partial
test_stale_finding_is_expired_or_deprioritized
test_two_independent_sources_increase_evidence_quality
test_contradictory_findings_are_retained_and_reconciled
test_parser_failure_is_not_reported_as_clean_success
```

## 15.3 Swarm

```text
test_stronger_finding_supersedes_weaker_board_finding
test_concurrent_conflicting_findings_are_deterministic
test_task_lease_expires
test_duplicate_task_is_idempotent
test_cancel_propagates_to_worker_and_process_group
test_worker_failure_does_not_corrupt_shared_state
test_partial_result_is_preserved_after_timeout
```

## 15.4 AutoMode

```text
test_action_has_explicit_expected_effect
test_success_requires_evidence_not_only_exit_code
test_planner_avoids_repeating_same_failed_move
test_planner_explains_rejected_candidates
test_planner_stops_when_budget_is_exhausted
test_planner_stops_on_scope_ambiguity
test_planner_marks_unknown_goal_as_unreached
test_replay_produces_deterministic_decision_trace
```

## 15.5 Electron/API

```text
test_every_ui_endpoint_is_allowlisted
test_every_ui_endpoint_is_reachable
test_payload_schema_matches_backend
test_http_error_does_not_set_optimistic_ui_state
test_remote_input_sends_text_once
test_remote_viewer_cannot_read_other_beacon_artifacts
test_token_rotation_updates_all_in_process_consumers
```

---

# 16. Roadmap prioritaria

## P0 — affidabilità e sicurezza di base

1. Implementare token provider runtime o reload atomico dopo rotation.
2. Separare gli artefatti remote per `beacon_id` con ownership verificata.
3. Correggere il modello di input testuale Electron.
4. Correggere lo stato ottimistico UI per status code/errori.
5. Rendere l’auth matrix un enforcement middleware reale.
6. Separare test hermetic da test che richiedono tool esterni.
7. Risolvere o classificare correttamente i failure della pipeline learned descriptor.

## P1 — AutoMode e tool discovery

1. Introdurre manifest versionato con schema forte.
2. Aggiungere provenienza, hash e stato di approvazione.
3. Separare discovered/candidate/approved/enabled.
4. Preferire argv typed a `shell=True`.
5. Centralizzare execution broker.
6. Sostituire first-writer-wins nei findings con merge evidence-aware.
7. Aggiungere outcome verification oltre all’exit code.
8. Implementare task leases, idempotency e cancellation end-to-end.

## P2 — enterprise quality

1. Secret store OS per API key.
2. Provider contracts e fixture offline.
3. Evidence TTL e freshness.
4. Calibrazione automatica dei confidence score.
5. Replay deterministico delle decisioni AutoMode.
6. Audit trail immutabile o append-only.
7. CI separata per unit, integration, Electron E2E e security sweep.
8. Capability health score basato su storico dei risultati.

---

# 17. Domande da sottoporre a DeepSeek

## Tool discovery

1. Qual è il miglior schema JSON per descrivere tool CLI con input tipizzati, output JSON/JSONL/line-based e capability effects?
2. Come separare in modo sicuro manifest, command builder, parser ed execution policy?
3. Come validare un tool nuovo usando solo `--help`, `--version` e fixture offline?
4. Come implementare una firma o un hash trust model per driver e manifest?
5. Come gestire versioni multiple dello stesso tool?
6. Come scegliere automaticamente tra tool equivalenti in base a costo, rumore, affidabilità e qualità dell’evidenza?

## AutoMode

1. Come progettare un belief model che distingua confidence, source reliability, evidence quality, freshness e independence?
2. Come trasformare WorldModel e swarm board in un merge evidence-aware e deterministico?
3. Come impedire che l’LLM dichiari confermati finding non dimostrati?
4. Come modellare expected effect e postcondition per ogni capability?
5. Come implementare decision trace riproducibili?
6. Come valutare automaticamente se il planner ha realmente raggiunto un goal?
7. Quali metriche usare per misurare AutoMode oltre alla percentuale di successo?

## Learning/evolution

1. Quali categorie di modifiche possono essere proposte automaticamente?
2. Quali file o componenti devono essere sempre protetti da review manuale?
3. Come generare replay fixture da un failure senza includere dati sensibili?
4. Come verificare che una patch learned non allarghi lo scope o i permessi?
5. Come progettare rollback e kill switch?

## Enterprise readiness

1. Quali invarianti di sicurezza devono essere testate a runtime e non solo con helper unitari?
2. Come progettare task leases, cancellation e process-tree cleanup multipiattaforma?
3. Come separare unit test hermetic, integration test e security sweep?
4. Come creare un audit log completo ma con redaction corretta?
5. Quali failure devono bloccare il merge e quali possono essere classificati come environment-dependent?

---

# 18. Criteri di accettazione finali

L’AutoMode e il sistema di tool discovery possono essere considerati maturi per una beta avanzata quando:

- un tool nuovo può essere importato senza modificare il catalogo statico;
- il tool nuovo non può essere eseguito prima dell’approvazione prevista dalla policy;
- ogni tool ha provenance, hash, versione e compatibilità registrati;
- gli input sono tipizzati e validati;
- i command normali usano argv, non shell string;
- ogni risultato è classificato con evidenza e provenance;
- l’exit code da solo non è sufficiente per dichiarare successo;
- finding contraddittori vengono reconciliati in modo deterministico;
- il board swarm non usa first-writer-wins per la verità dei finding;
- ogni task è cancellabile e idempotente;
- il planner registra candidate, scelta, scarto e postcondition;
- i replay producono decision trace riproducibili;
- l’LLM può proporre ma non bypassare policy;
- learning/evolution lavora su branch separati;
- le patch passano test hermetic, security e regression;
- Electron e backend hanno contratti verificati automaticamente;
- la suite obbligatoria è verde senza dipendere accidentalmente dai tool installati sul computer dello sviluppatore.

---

# 19. Conclusione

Phantom ha una base architetturale seria e originale. Il valore principale non è soltanto il numero di comandi disponibili, ma il tentativo di costruire un sistema che rappresenti esplicitamente:

- ciò che sa;
- quanto lo sa;
- da dove proviene l’informazione;
- quali ipotesi sono ancora aperte;
- quali azioni sono autorizzate;
- quali azioni sono rumorose;
- quali errori sono già stati osservati;
- quando deve fermarsi.

La gestione dinamica dei tool è fattibile e dovrebbe diventare una delle caratteristiche distintive di Phantom. Tuttavia il sistema deve evolvere da:

```text
manifest trovato → capability eseguibile
```

a:

```text
tool scoperto
→ manifest candidato
→ validazione
→ approval policy
→ capability tipizzata
→ execution broker
→ evidenza verificata
→ merge nel WorldModel
```

L’AutoMode è già abbastanza avanzato da meritare ulteriori investimenti, ma il passo successivo non dovrebbe essere semplicemente aggiungere più moduli o più tecniche. Le priorità più importanti sono:

1. **evidence-driven planning**;
2. **capability trust e approval workflow**;
3. **belief merge corretto e deterministico**;
4. **verifica delle postcondition**;
5. **cancellation, provenance e auditabilità**.

Se queste aree vengono risolte, Phantom può passare da un orchestratore molto ambizioso a una piattaforma agentica realmente più affidabile, verificabile e credibile in contesti enterprise autorizzati.
