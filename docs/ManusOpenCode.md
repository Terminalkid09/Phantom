# Phantom — Audit architetturale e piano di miglioramento operativo

**Data:** 7 ottobre 2026  
**Branch analizzato:** `dev`  
**Ambito:** Beacon, AutoMode, core manuale, C2, CLI, Electron e help contestuale  
**Autore:** Manus AI

> **Sintesi esecutiva:** Phantom ha ormai tre superfici mature ma diverse: un orchestratore AutoMode, un core manuale modulare e una control plane C2. Non è necessario fonderle in un unico componente. È invece necessario renderle un unico prodotto operativo, con contesti espliciti, stato condiviso, handoff bidirezionale e help filtrato in base al contesto corrente.

---

## 1. Giudizio complessivo

Il progetto è cresciuto oltre il modello di un semplice framework CLI. Oggi contiene almeno quattro livelli distinti:

1. **Orchestrazione:** AutoMode, agenti multipli, swarm, reasoning, checkpoint ed evolution.
2. **Analisi manuale:** moduli di scan, web, OSINT, AD graph, exploit, payload, pivot e report.
3. **Control plane:** listener C2, generazione beacon, elenco beacon, task, risultati, autenticazione e sessioni remote.
4. **Interfacce operatore:** CLI, Electron, pannelli di audit, timeline, vault, network map e learning.

La separazione tecnica è sensata. Il problema attuale è soprattutto di **coerenza operativa**:

- il comando `phantom` apre AutoMode per default;
- il core manuale esiste come modalità interna di AutoMode oppure come entry point separato `--manual`;
- il C2 è accessibile dal core manuale tramite `c2`, ma il passaggio diretto AutoMode → C2 non è esposto in modo equivalente nella UI Electron;
- il C2 mescola comandi globali, generazione di payload e comandi eseguibili soltanto dentro un beacon;
- `help` mostra troppe informazioni in un unico livello;
- la CLI e Electron rappresentano concetti simili con modelli di navigazione diversi.

Il risultato è che l’architettura interna è più ordinata di quanto appaia all’operatore.

### Valutazione sintetica

| Area | Valutazione attuale | Giudizio |
|---|---:|---|
| Architettura complessiva | 7,5/10 | Buona separazione, ma manca un modello esplicito degli stati operativi |
| AutoMode | 7/10 | Orchestratore avanzato, non ancora executor universale end-to-end |
| Core manuale | 7,5/10 | Ricco e modulare, ma deve essere più facilmente raggiungibile |
| C2 | 7,5/10 | Control plane ricca, con help e contesti da rifinire |
| Beacon | 6,5–7/10 | Protocollo serio, ma resta da correggere il lifecycle dei task timeout |
| Electron | 7,5/10 | Buona base e stato persistente, ma manca un workflow di handoff completo |
| CLI UX | 6,5/10 | Potente, ma help e contesti sono troppo aggregati |
| Prontezza enterprise | 6–7/10 | Buona piattaforma di security validation autorizzata, non ancora universale |

---

## 2. Modello architetturale raccomandato

### 2.1 Non fondere tutto in un unico shell

La scelta consigliata è mantenere tre contesti principali:

| Contesto | Responsabilità | Deve conoscere |
|---|---|---|
| **AutoMode** | Pianificazione, reasoning, agenti, esecuzione controllata e gestione checkpoint | Sessione, scope, evidenze, stato del run e beacon disponibili |
| **Manual Core** | Analisi guidata dall’operatore, moduli, AD graph, OSINT, report e comandi deterministici | Sessione, target, scope, findings, risultati AutoMode e stato C2 |
| **C2 Control Plane** | Listener, payload autorizzati, beacon registry, task, risultati e remote session | Beacon, autenticazione, capability del beacon e audit C2 |

Questi contesti non devono diventare tre applicazioni indipendenti. Devono essere tre **workspace della stessa engagement session**.

La regola architetturale dovrebbe essere:

> Un solo stato di engagement, tre viste operative, handoff espliciti e capability filtrate dal contesto.

### 2.2 Il problema dell’attuale default

In `phantom/main.py`, il bare command `phantom` apre AutoMode. Questa decisione è coerente con l’obiettivo di rendere AutoMode il punto d’ingresso principale, ma crea due effetti collaterali:

- un utente che vuole usare il core manuale deve conoscere `manual` oppure `phantom --manual`;
- un utente che vuole passare subito al C2 deve attraversare il core manuale oppure usare un entry point dedicato.

Non è necessario ripristinare il core manuale come default. È preferibile rendere il default AutoMode più esplicito e aggiungere una **Control Room globale**.

### 2.3 Flusso operativo raccomandato

```text
phantom
  └── Engagement Control Room
        ├── AutoMode
        ├── Manual Core
        ├── C2 Control Plane
        ├── Evidence / Timeline
        └── Session / Scope
```

In CLI, la Control Room può essere rappresentata dal prompt e dai comandi di navigazione. In Electron è già rappresentata parzialmente dalla Sidebar, ma deve essere completata con handoff visibili.

---

## 3. AutoMode

### 3.1 Cosa è forte

AutoMode ha già caratteristiche che lo distinguono da un semplice wrapper di comandi:

- target multipli;
- profili di ragionamento;
- modalità aggressive e stealth come profili operativi, non come garanzia di invisibilità;
- conteggio agenti e workers per target;
- swarm orchestration;
- checkpoint e resume;
- experience e learning memory;
- LLM advisor opzionale;
- stream degli eventi;
- step dinamici;
- deduplicazione del reasoning stream;
- stop esplicito;
- integrazione con sessione e knowledge model;
- handoff C2 quando viene ottenuto un beacon;
- bridge dei risultati verso il core manuale.

Il calcolo degli agenti è stato migliorato: quando il numero di agenti supera il numero di target, gli agenti eccedenti possono diventare workers sullo stesso target invece di essere ignorati silenziosamente.

### 3.2 Limite principale

AutoMode non deve essere giudicato soltanto dal fatto che sappia scegliere e lanciare una capability. Deve essere giudicato dal ciclo completo:

```text
precondition
→ action
→ output parsing
→ postcondition
→ evidence classification
→ confidence update
→ next decision
```

Il rischio più importante è confondere:

```text
azione terminata senza eccezione = successo
```

con:

```text
obiettivo verificato da evidenza indipendente = successo
```

La seconda semantica è quella necessaria per un engagement serio.

### 3.3 Miglioramenti prioritari

#### A. Stato esplicito del run

Ogni run dovrebbe avere uno stato pubblico e persistente:

- `PLANNING`;
- `RUNNING`;
- `WAITING_FOR_OPERATOR`;
- `WAITING_FOR_BEACON`;
- `HANDOFF_READY`;
- `PAUSED`;
- `STOPPING`;
- `COMPLETED`;
- `FAILED`;
- `PARTIAL`.

Il caso `HANDOFF_READY` è fondamentale: indica che AutoMode ha terminato la parte autonoma e aspetta che l’operatore decida se entrare nel C2.

#### B. Precondition e postcondition tipizzate

Ogni capability dovrebbe esporre almeno:

```text
requires: [facts]
produces: [facts]
postconditions: [checks]
side_effects: [declared effects]
rollback: [available or not]
operator_confirmation: [required or not]
```

#### C. Handoff non implicito

L’handoff automatico diretto a `run_c2(preferred_beacon=...)` è utile nella CLI, ma non dovrebbe essere l’unico comportamento. Deve essere configurabile:

- `auto-handoff`: entra nel C2 automaticamente;
- `prompt-handoff`: mostra una scelta all’operatore;
- `stay-in-automode`: termina AutoMode e lascia il beacon disponibile;
- `no-c2`: non apre il C2 ma registra l’evento.

Per default suggerisco `prompt-handoff`.

#### D. Validità del risultato

Il planner dovrebbe distinguere almeno:

| Risultato | Significato |
|---|---|
| `confirmed` | Precondition, azione e postcondition verificate |
| `probable` | Evidenza consistente ma incompleta |
| `negative` | Test eseguito e risultato negativo |
| `inconclusive` | Il test non permette una conclusione |
| `blocked` | Mancano permessi, tool, rete o scope |
| `failed` | Errore dell’azione o dell’adapter |

Questa distinzione deve arrivare sia nella Timeline sia nella UI AutoMode.

---

## 4. Passaggio AutoMode → C2

### 4.1 Stato attuale

Nel backend esiste già un percorso di handoff:

- AutoMode rileva un beacon;
- stampa il messaggio di passaggio all’operatore;
- invoca `run_c2(preferred_beacon=beacon_id)`;
- il C2 può aprire direttamente il contesto del beacon preferito.

Il core manuale possiede inoltre il comando `c2`, che invoca `run_c2()`.

Questo significa che la capacità backend esiste. Il problema è di **uniformità e scopribilità**, soprattutto in Electron.

### 4.2 Cosa manca

Manca un contratto di handoff comune, per esempio:

```json
{
  "source": "automode",
  "engagement_id": "...",
  "beacon_id": "B-...",
  "reason": "beacon_established",
  "status": "ready",
  "recommended_action": "open_c2_interact",
  "created_at": "..."
}
```

Questo record dovrebbe essere visibile in:

- AutoMode panel;
- StatusBar;
- Timeline;
- C2 Dashboard;
- Command Palette;
- CLI prompt.

### 4.3 UX consigliata in Electron

Quando appare un beacon live durante o dopo AutoMode, il pannello dovrebbe mostrare una card persistente:

> **Beacon disponibile — B-7F3A**  
> Target: `target-name` · OS: Windows · Ultimo check-in: 4 s fa  
> **[Apri C2] [Interagisci] [Mantieni in AutoMode] [Dettagli]**

Il pulsante **Apri C2** deve:

1. impostare `activeBeacon` nello store;
2. cambiare `activeTab` in `c2`;
3. impostare il contesto C2 su `interact`;
4. mostrare il beacon selezionato;
5. aggiungere un evento alla Timeline;
6. non avviare automaticamente task sul beacon.

Il pulsante **Interagisci** deve fare lo stesso, ma portare direttamente all’area task.

### 4.4 Handoff inverso

Deve esistere anche:

```text
C2 → AutoMode
```

Esempi:

- usare un beacon come fatto disponibile per AutoMode;
- chiedere ad AutoMode di analizzare i risultati raccolti;
- avviare un run post-accesso limitato a uno specifico beacon;
- riportare un task C2 nella knowledge base senza creare duplicati.

---

## 5. Core manuale

### 5.1 Valutazione

Il core manuale è più importante di quanto suggerisca il nuovo default AutoMode. È il luogo in cui l’operatore può:

- correggere il piano;
- eseguire un modulo specifico;
- usare OSINT e social graph in modo controllato;
- analizzare l’AD graph e i percorsi BloodHound-style;
- eseguire comandi con preview interattivo;
- verificare un finding;
- costruire payload autorizzati;
- leggere e modificare il contesto di sessione;
- produrre report.

La scelta corretta non è eliminarlo, ma renderlo una **modalità manuale di primo livello**.

### 5.2 Miglioramento di navigazione CLI

Nel prompt AutoMode, il comando attuale `manual` è corretto ma poco visibile. Suggerisco di aggiungere:

```text
manual                 Apri il Manual Core mantenendo la sessione corrente
c2                     Apri la C2 Control Plane
handoff                Mostra handoff disponibili
context                Mostra target, scope, run, beacon e modalità correnti
workspace              Mostra tutte le superfici disponibili
```

Il comando `c2` dovrebbe essere disponibile direttamente da AutoMode, non soltanto dal manuale.

Il comando `manual` dovrebbe restituire al prompt AutoMode con `back` senza ambiguità.

### 5.3 Prompt contestuali

I prompt dovrebbero rendere evidente il contesto:

```text
[phantom][AUTO][target: example.com] >
[phantom][MANUAL][target: example.com] >
[phantom][C2][global] >
[phantom][C2][beacon:B-7F3A] >
```

Questo riduce il rischio di inviare un comando al posto sbagliato.

---

## 6. C2: separazione dei due help

La tua proposta è corretta. Il C2 ha attualmente un unico `help` che mescola:

- listener;
- TLS e mTLS;
- configurazione;
- beacon registry;
- interazione beacon;
- comandi post-accesso;
- remote session;
- payload generation;
- audit;
- Telegram.

Questa lista è tecnicamente completa ma operativamente troppo piatta.

### 6.1 Help globale C2

Quando non è selezionato alcun beacon, `help` dovrebbe mostrare solo il contesto globale:

```text
C2 GLOBAL COMMANDS

Listener
  listeners                 Stato del listener
  listeners start ...       Avvia il listener
  listeners stop            Ferma il listener
  certs ...                 Gestisce certificati
  config ...                Stato, token e mTLS

Beacons
  beacons                   Elenca beacon registrati
  interact <id>             Entra nel contesto di un beacon
  beacon-auth ...           Gestisce identità e revoca
  audit ...                 Visualizza e verifica l’audit log

Payloads
  generate                  Genera un beacon
  generate-shellcode        Genera shellcode per un artefatto già selezionato
  payloads                  Elenca artefatti già generati

Navigation
  help                     Mostra questo help
  help generate            Dettagli della generazione
  beacon-help              Mostra i comandi agent disponibili
  exit                    Chiude il C2
```

Il comando `generate` deve essere elencato esplicitamente con la sintassi supportata:

```text
generate [windows|linux|macos|android] [x64|x86] [--profile <json>]
```

Deve anche indicare che, senza piattaforma e in sessione interattiva, viene mostrato il selettore.

Esempio di help dettagliato:

```text
help generate

generate [platform] [arch] [--profile <path>]

Piattaforme: windows, linux, macos, android
Architetture: x64, x86 dove supportato

Senza platform:
  - usa una classificazione OS già presente nella sessione;
  - se non esiste, apre il selettore interattivo;
  - in modalità non interattiva richiede platform esplicita.

Prerequisiti consigliati:
  listeners start
  config status

Output:
  - artefatto compilato;
  - comando o dropper associato;
  - registrazione nel payload inventory.
```

### 6.2 Help contestuale beacon

Dopo:

```text
interact <beacon-id>
```

il prompt deve cambiare:

```text
[phantom][C2][beacon:B-7F3A] >
```

A quel punto `help` deve mostrare soltanto comandi inviabili al beacon selezionato:

```text
BEACON CONTEXT — B-7F3A

Session
  health                    Stato, uptime e check-in
  results [n|all]           Risultati recenti
  set-sleep <ms> [jitter]   Modifica cadenza
  back                      Torna al C2 globale

Collection
  screenshot               Richiede uno screenshot
  wlan                     Richiede informazioni Wi-Fi
  gps                      Richiede posizione se supportata
  screen-watch [gui]       Visualizza registrazioni se disponibili
  remote ...               Avvia il modulo remote autorizzato

Beacon lifecycle
  keylog start|stop|status|dump
  persist [method]
  autopersist

Advanced
  inject ...
  migrate
  mem-run ...

Help
  help                    Mostra questo elenco
  help screenshot         Dettagli del comando
  beacon-help             Elenco raw delle capability del beacon
```

### 6.3 Non mostrare comandi non validi

I comandi devono essere filtrati con tre livelli:

1. **Contesto:** globale oppure beacon.
2. **Capability:** il beacon supporta davvero il comando?
3. **Stato:** il comando è disponibile con beacon offline, listener fermo o nessuna sessione?

Per esempio:

- `generate` è globale;
- `screenshot` è beacon-scoped;
- `generate-shellcode` richiede un artefatto e un contesto di build valido;
- `remote-view` richiede una remote session attiva;
- `results` richiede un beacon selezionato;
- `persist` richiede beacon, OS compatibile e input di percorso.

### 6.4 Registry unico degli help

Non mantenere help separati scritti manualmente in più file. Crea un registry con metadati:

```python
CommandSpec(
    name="screenshot",
    scope="beacon",
    category="collection",
    requires=("active_beacon",),
    capabilities=("screenshot",),
    risk="high",
    description="Richiede uno screenshot al beacon selezionato",
    usage="screenshot",
)
```

Lo stesso registry può alimentare:

- CLI `help`;
- CLI autocompletion;
- Electron Beacon Help;
- Command Palette;
- documentazione generata;
- controlli di disponibilità.

---

## 7. Problema specifico del comando `generate`

La logica di `generate` è più ricca di quanto comunichi l’help attuale.

Il comportamento osservato comprende:

- rilevazione della piattaforma da risultati della sessione;
- selettore interattivo se la piattaforma non è conosciuta;
- fallback non interattivo;
- validazione platform;
- confronto tra piattaforma rilevata e artefatto richiesto;
- selezione architettura;
- compilazione del beacon;
- generazione del dropper;
- gestione del listener attivo o fermo;
- registrazione del payload custom;
- eventuale proposta di deployment.

Questa è una procedura a più fasi. L’help dovrebbe comunicarlo e il comando dovrebbe stampare uno stato strutturato:

```text
[1/5] Platform selection
[2/5] Architecture validation
[3/5] Beacon compilation
[4/5] Dropper generation
[5/5] Payload registration
```

Se il listener non è attivo, il comportamento dovrebbe essere esplicito:

```text
Listener non attivo.
Il payload può essere generato, ma il callback non sarà ricevuto finché non avvii:
  listeners start
```

Non deve apparire come un errore di compilazione.

In modalità non interattiva, il fallback implicito a Windows è discutibile. È più sicuro e più riproducibile richiedere:

```text
generate --platform windows --arch x64
```

oppure terminare con un errore chiaro se la piattaforma non è stata determinata.

---

## 8. Electron

### 8.1 Cosa funziona bene

Electron ha una base solida:

- pannelli separati per C2, sessione e AutoMode;
- stato globale tramite store;
- polling serializzato nell’AutoMode;
- polling C2 centralizzato nell’hook API;
- capability gating;
- pannelli mantenuti montati per non perdere lo stato locale;
- Command Palette;
- Timeline, Audit, Learning, AD Graph e Network Map;
- C2 Dashboard con listener, beacon list, interact, results e remote canvas;
- pannelli separati per Generate, Auth, Certs e Beacon Help.

La UI quindi contiene già quasi tutti i mattoni per il workflow richiesto.

### 8.2 Lacuna principale: AutoMode non ha un’azione C2 evidente

`AutoModePanel` avvia il run, riceve gli stream e alla fine esegue `pollC2()`. Questo aggiorna lo stato dei beacon, ma non equivale a un handoff UX.

Dopo la comparsa di un beacon, l’operatore deve:

1. accorgersi che il beacon esiste;
2. andare manualmente in C2 Dashboard;
3. selezionarlo;
4. scegliere interact.

Il backend sa già fare di più, ma Electron non lo comunica.

### 8.3 Modifiche UI consigliate

#### AutoModePanel
Aggiungere:

- card `Handoff ready`;
- beacon appena creato;
- stato `LIVE/OFFLINE/STALE`;
- pulsante `Open C2`;
- pulsante `Interact`;
- pulsante `View timeline`;
- pulsante `Keep AutoMode open`;
- link alla sessione e al target.

#### C2Dashboard
Aggiungere:

- breadcrumb `C2 / Global` oppure `C2 / Beacon B-...`;
- titolo contestuale;
- tab separati `Global`, `Generate`, `Beacons`, `Interact`, `Help`;
- help globale quando non esiste `activeBeacon`;
- help beacon quando esiste `activeBeacon`;
- indicazione dei prerequisiti per ogni pulsante;
- stato dei comandi `available`, `blocked`, `unsupported`, `requires approval`.

#### Sidebar
La sidebar può restare con `C2 Dashboard`, `Session`, `Auto-Mode` e moduli. Suggerisco però di aggiungere indicatori:

- badge `handoff ready` su AutoMode;
- badge numero beacon live su C2;
- badge `run active` su AutoMode;
- stato colore per C2 connesso/disconnesso.

#### Command Palette
Dovrebbe includere azioni contestuali:

```text
Open AutoMode
Open Manual Core
Open C2 Global
Open active beacon
Open latest handoff
Open Timeline for current target
```

### 8.4 Stato condiviso da aggiungere

Lo store dovrebbe contenere un modello esplicito:

```ts
interface HandoffState {
  id: string
  source: 'automode' | 'manual' | 'c2'
  kind: 'beacon_established' | 'task_result' | 'remote_ready'
  beaconId?: string
  target?: string
  status: 'ready' | 'accepted' | 'dismissed' | 'expired'
  createdAt: string
}
```

Questo evita che ogni pannello debba inferire il contesto osservando solo `beacons` o `autoMode.running`.

---

## 9. Beacon

### 9.1 Aspetti positivi

Il beacon ha una base importante:

- retry e backoff;
- endpoint ladder;
- HMAC e identità per beacon;
- replay protection;
- mTLS e certificate pinning;
- limite output;
- task timeout;
- health counters;
- supporto multipiattaforma;
- comandi di raccolta e gestione;
- remote session separata;
- test di trasporto e autenticazione.

### 9.2 Problema di lifecycle dei task

Il problema più serio già individuato resta nel watchdog di `main.cpp`.

Il codice crea `TaskRun` sullo stack, avvia un thread e, in caso di timeout, effettua `detach()` mentre il worker può ancora usare il puntatore a `TaskRun`.

Questo può produrre:

- use-after-free;
- data race;
- crash;
- output scritto in memoria non più valida;
- processi figli ancora attivi dopo il timeout.

Il timeout attuale interrompe l’attesa del beacon, ma non garantisce l’interruzione reale dell’azione sottostante.

### 9.3 Correzione architetturale

La soluzione dovrebbe usare:

- un oggetto task con lifetime condiviso;
- un cancellation token;
- process group/session dedicata;
- terminazione esplicita del gruppo;
- `waitpid` o equivalente garantito;
- limite al numero di task simultanei;
- stato terminale persistente;
- cleanup in caso di shutdown;
- test su pipe che non chiudono, processi figli e processi bloccati.

Il risultato deve distinguere:

```text
completed
failed
cancelled
timed_out
killed
orphan_reaped
```

### 9.4 Evasion e stabilità

La presenza di primitive anti-analysis non dimostra l’evasione da EDR moderni. Per Phantom è più professionale descriverle come:

> primitive di anti-analysis, detection-awareness e compatibilità di runtime, da validare in laboratorio tramite telemetria.

Il progetto non dovrebbe promettere invisibilità o bypass universale. La validazione enterprise deve misurare eventi di detection, errori, degradazioni e compatibilità.

---

## 10. Contratto di capability

Per rendere coerenti CLI, Electron, AutoMode e C2, ogni capability dovrebbe avere un contratto comune:

```json
{
  "id": "screenshot",
  "surface": "beacon",
  "scope": "active_beacon",
  "category": "collection",
  "platforms": ["windows", "linux", "macos"],
  "requires": ["active_beacon", "capability:screenshot"],
  "produces": ["artifact:screenshot"],
  "risk": "high",
  "requires_confirmation": true,
  "status": "implemented",
  "validation": "unit_and_lab",
  "help": "..."
}
```

Lo status deve distinguere:

- `implemented`;
- `unit_tested`;
- `integration_tested`;
- `lab_validated`;
- `platform_limited`;
- `placeholder`;
- `unsupported`.

Questo è particolarmente importante per media capture, Android, macOS, HID, remote session e tool esterni.

---

## 11. Piano di implementazione consigliato

### P0 — navigazione e contesto

1. Aggiungere `c2` direttamente ad AutoShell.
2. Rendere visibile `manual` nell’help AutoMode.
3. Aggiungere `context`, `workspace` e `handoff`.
4. Aggiungere prompt contestuali.
5. Creare un handoff record condiviso.
6. Aggiungere card AutoMode → C2 in Electron.

### P1 — help e command registry

1. Separare `help` globale C2 da `help` beacon.
2. Documentare `generate` in modo esplicito.
3. Documentare il selettore interattivo e i prerequisiti.
4. Filtrare i comandi per contesto, capability e stato.
5. Creare un registry unico degli help.
6. Riutilizzare il registry per CLI, Electron e autocompletion.

### P1 — stabilità beacon

1. Correggere il lifetime di `TaskRun`.
2. Terminare realmente processi e process groups al timeout.
3. Aggiungere test di orphan prevention.
4. Distinguere timeout, cancel e kill.
5. Aggiungere un limite ai worker detached, idealmente eliminandoli.

### P2 — AutoMode enterprise quality

1. Aggiungere postcondition tipizzate.
2. Separare `confirmed`, `probable`, `negative`, `inconclusive`, `blocked` e `failed`.
3. Rendere l’handoff configurabile.
4. Aggiungere resume da `WAITING_FOR_OPERATOR`.
5. Collegare ogni azione a evidence provenance.
6. Visualizzare il motivo della scelta del prossimo step.

### P2 — Electron workflow

1. Aggiungere breadcrumb di contesto.
2. Aggiungere badge di handoff.
3. Aggiungere pulsanti Open C2 e Interact nel pannello AutoMode.
4. Aggiungere C2 Global Help e Beacon Help distinti.
5. Aggiungere quick actions nella Command Palette.
6. Mostrare prerequisiti e motivi dei comandi disabilitati.

### P3 — validazione end-to-end

1. Matrice per OS e architettura.
2. Test reali su board HID.
3. Test C2 con perdita rete e rotazione certificati.
4. Test beacon con task bloccati e processi figli.
5. Test AutoMode con risultati contraddittori.
6. Test Electron su handoff e restart backend.

---

## 12. Test di accettazione

### CLI

- `phantom` apre AutoMode.
- `help` mostra `manual`, `c2`, `context`, `handoff`.
- `c2` apre il C2 direttamente da AutoMode.
- `manual` apre il core manuale mantenendo target, scope e findings.
- `back` ritorna al contesto precedente.
- Il prompt identifica sempre il contesto corrente.

### C2 globale

- `help` non mostra comandi esclusivamente beacon senza indicazione del prerequisito.
- `help generate` documenta piattaforme, architetture, selettore e prerequisiti.
- `generate` senza argomenti apre il selettore solo in modalità interattiva.
- In modalità non interattiva, la piattaforma deve essere esplicita o determinata senza fallback ambiguo.
- `beacons` e `interact <id>` sono immediatamente visibili.

### C2 beacon

- Dopo `interact <id>`, il prompt cambia.
- `help` mostra soltanto comandi validi per il beacon.
- `back` torna al contesto globale senza perdere il beacon selezionato.
- Comandi non supportati vengono marcati come non disponibili.
- `results`, `screenshot`, `health` e `wlan` mostrano prerequisiti e stato.

### Electron

- Un beacon live durante AutoMode genera una card handoff.
- `Open C2` cambia tab e seleziona il beacon.
- `Interact` apre direttamente l’area task.
- Lo stato sopravvive al cambio pannello.
- Il restart del backend mostra un errore esplicito e non una UI apparentemente vuota.

### Beacon

- Un task timeout non lascia processi figli attivi.
- Un task cancel restituisce uno stato distinto da timeout.
- Lo shutdown ripulisce worker e processi.
- Un risultato tardivo non scrive memoria liberata.
- Il beacon continua il loop dopo un task fallito senza perdita di stato.

---

## 13. Conclusione

La decisione consigliata è mantenere **AutoMode, Manual Core e C2 come tre contesti distinti**, ma inserirli in un’unica engagement control room.

Non suggerisco di tornare al core manuale come avvio predefinito. AutoMode può rimanere il punto d’ingresso principale, perché rappresenta la direzione strategica del progetto. Tuttavia deve offrire immediatamente:

```text
manual
c2
handoff
context
```

La priorità UX più evidente è separare il C2 in:

1. **contesto globale**, con listener, generate, payloads, beacons, auth, certs e audit;
2. **contesto beacon**, con screenshot, health, results, keylog, wlan, remote e altre capability effettivamente disponibili.

La priorità tecnica più importante resta il lifecycle dei task del beacon. Prima di aumentare ulteriormente il numero di capability, Phantom dovrebbe garantire che un timeout sia un timeout reale, che non restino processi orfani e che l’AutoMode sappia distinguere un’azione terminata da un obiettivo realmente verificato.

Il progetto è già abbastanza ricco per diventare una piattaforma professionale di security validation autorizzata. Il salto successivo non richiede soltanto nuove feature. Richiede soprattutto **coerenza dello stato, handoff chiari, help contestuale, postcondition verificabili e test end-to-end**.

---

## Riferimenti

[1]: https://github.com/Terminalkid09/Phantom "Phantom repository"
[2]: https://docs.python.org/3/library/cmd.html "Python cmd module documentation"
[3]: https://www.electronjs.org/docs/latest/tutorial/security "Electron security documentation"
