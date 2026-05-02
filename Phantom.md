# Phantom — Project Specification

> Documento di riferimento per sviluppo assistito da AI (Claude, GitHub Copilot, Qwen3-Coder-30B)

---

## Panoramica

**Phantom** è una shell interattiva CLI per penetration testing, installabile su Kali Linux, open source e completamente gratuita. Non è un semplice wrapper — è un'interfaccia con stato che orchestra tool esistenti (Nmap, Gobuster, Hydra, SQLmap, Metasploit, e altri) in un'unica sessione coerente, con preview modificabile dei comandi prima dell'esecuzione e logica condizionale intelligente.

**Obiettivo:** Sostituire il workflow manuale di un pentester (cheatsheet, copia-incolla tra tool, comandi a memoria) con un'interfaccia professionale che mantiene il controllo totale nelle mani dell'operatore.

**Linguaggio:** Python 3.10+ **Target OS:** Kali Linux (compatibile con qualsiasi Linux con i tool necessari installati) **Distribuzione:** Open source su GitHub, installabile via `pip install -e .`

---

## Principi di Design

1. **L'operatore decide sempre.** Il tool suggerisce, non esegue autonomamente. Nessun comando parte senza approvazione esplicita.
2. **Preview prima di tutto.** Ogni modulo mostra i comandi raggruppati per tipologia prima di eseguire. L'operatore può modificare, rimuovere, aggiungere comandi prima del run.
3. **Stato persistente per sessione.** Il target, i risultati, i preset vengono mantenuti durante tutta la sessione senza doverli riscrivere.
4. **Modulare.** Ogni modulo è un file Python indipendente con una responsabilità ben definita. Aggiungere un nuovo modulo non rompe il resto.
5. **Nessuna dipendenza esterna a pagamento.** Tutte le API usate sono gratuite (NVD, ExploitDB, crt.sh, whois, Shodan free tier).
6. **Offline-first.** Il core funziona senza internet. Le feature che richiedono API sono opzionali e gestite con fallback.

---

## Architettura del Progetto

```
phantom/
├── phantom/
│   ├── __init__.py
│   ├── main.py                  # Entry point, avvia la shell
│   ├── core/
│   │   ├── __init__.py
│   │   ├── shell.py             # Shell interattiva principale (cmd.Cmd)
│   │   ├── session.py           # Stato globale della sessione (target, risultati, preset, note)
│   │   ├── preview.py           # Sistema di preview e modifica comandi
│   │   ├── executor.py          # Esecuzione comandi con subprocess, output capture
│   │   ├── scope.py             # Scope management — whitelist IP/subnet, warning fuori scope
│   │   ├── notes.py             # Note inline durante sessione
│   │   └── logger.py            # Logging sessione su file
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── base_module.py       # Classe base che tutti i moduli estendono
│   │   ├── scan.py              # Modulo Scan/Network Recon
│   │   ├── osint.py             # Modulo OSINT
│   │   ├── web.py               # Modulo Web (Gobuster, SQLmap, fuzzing)
│   │   ├── brute.py             # Modulo Brute Force (Hydra)
│   │   ├── exploit.py           # Modulo Exploitation (Metasploit wrapper + CVE + exploitability score)
│   │   ├── payload.py           # Modulo Payload Generator (msfvenom wizard + listener)
│   │   ├── handler.py           # Modulo Reverse Shell Handler (listener integrato)
│   │   ├── pivot.py             # Modulo Port Forwarding / Pivoting helper
│   │   ├── analyzer.py          # Modulo pcap analysis
│   │   └── report.py            # Generazione report PDF/HTML
│   └── utils/
│       ├── __init__.py
│       ├── api.py               # Client per API esterne (NVD, ExploitDB, crt.sh, Shodan)
│       ├── parser.py            # Parsing output Nmap XML, JSON
│       ├── wordlists.py         # Wordlist manager — indicizza, categorizza, seleziona
│       └── formatter.py        # Output colorato con rich
├── data/
│   ├── presets/                 # Preset salvati dall'utente (JSON)
│   └── sessions/               # Sessioni salvate con tutti i risultati (JSON)
├── setup.py
├── requirements.txt
└── README.md
```

---

## Shell Interattiva

Implementata con il modulo stdlib `cmd.Cmd` di Python. La shell mantiene uno stato globale (`Session`) accessibile da tutti i moduli.

### Comandi globali disponibili ovunque

```
set target <ip/domain>          # Imposta il target della sessione
set scope <cidr/ip,ip,...>      # Definisce IP/subnet in scope — warning se fuori scope
set mode <recon|full|exploit|osint>  # Modalità operativa
show session                    # Mostra stato attuale (target, modalità, risultati)
show presets                    # Lista preset salvati
show scope                      # Mostra scope corrente
load-preset <nome>              # Carica un preset
save-preset <nome>              # Salva configurazione corrente come preset
save-session <nome>             # Salva sessione completa su disco (riprendi dopo)
load-session <nome>             # Carica sessione precedente con tutti i risultati
list-sessions                   # Lista sessioni salvate con data e target
note "<testo>"                  # Aggiunge nota inline — finisce nel report automaticamente
notes                           # Mostra tutte le note della sessione corrente
capture                         # Salva output corrente come snapshot nel report
history                         # Mostra comandi eseguiti in sessione
export <json|pdf|html>          # Esporta risultati sessione
use <modulo>                    # Entra in un modulo
back                            # Torna alla shell principale
help                            # Help contestuale
exit / quit                     # Chiude phantom (chiede se salvare sessione)
```

### Modalità operative

- `recon` — Solo scan e OSINT, nessun exploit. Per fase di ricognizione.
- `osint` — Solo OSINT passivo, nessun contatto diretto col target.
- `full` — Tutto abilitato, scan + exploitation.
- `exploit` — Salta recon, vai diretto all'exploitation (richiede risultati già presenti in sessione).

---

## Sistema di Preview e Modifica

Ogni modulo, prima di eseguire qualsiasi comando, chiama `preview.py` che mostra i comandi raggruppati per tipologia. L'operatore interagisce con il preview prima dell'esecuzione.

### Struttura del preview

```
[scan] > preview

  ── NMAP ────────────────────────────────────────────────────────────
  [1]  sudo nmap -sS -p- --min-rate 5000 -T4 10.0.0.1
  [2]  sudo nmap -sV -sC -p 22,80,443,8080 10.0.0.1
  [3]  sudo nmap -sU --top-ports 200 10.0.0.1
  [4]  sudo nmap --script vuln -p 22,80,443 10.0.0.1
  [5]  sudo nmap -O 10.0.0.1

  ── NETWORK ─────────────────────────────────────────────────────────
  [6]  traceroute 10.0.0.1
  [7]  sudo arp-scan --localnet
  [8]  ping -c 4 10.0.0.1

  ── SERVICE ENUM ────────────────────────────────────────────────────
  [9]  nc -nv 10.0.0.1 22
  [10] sslscan 10.0.0.1:443
  [11] enum4linux -a 10.0.0.1
  [12] snmpwalk -c public -v1 10.0.0.1

  ── COMANDI AGGRESSIVI (conferma richiesta) ─────────────────────────
  [13] sudo nmap --script exploit 10.0.0.1   ⚠ AGGRESSIVO

  edit [n]            → modifica comando specifico
  remove [n]          → rimuove comando
  add                 → aggiunge comando custom
  run-group [nome]    → esegue solo quel gruppo
  run-all             → esegue tutto
  cancel              → annulla
```

### Logica di modifica

```python
# preview.py — struttura base
class PreviewSession:
    def __init__(self, groups: dict[str, list[str]]):
        self.groups = groups  # {"NMAP": ["cmd1", "cmd2"], "NETWORK": [...]}
    
    def edit(self, index: int, new_cmd: str): ...
    def remove(self, index: int): ...
    def add(self, group: str, cmd: str): ...
    def run_group(self, group_name: str): ...
    def run_all(self): ...
```

---

## Moduli — Dettaglio Completo

### 1. Modulo SCAN

Orchestrazione intelligente di Nmap e tool di network recon. La logica condizionale analizza i risultati di ogni step e suggerisce il passo successivo.

**Comandi gestiti:**

NMAP:

- `sudo nmap -sS -p- --min-rate 5000 -T4 <target>` — SYN scan completo
- `sudo nmap -sS --top-ports 1000 <target>` — Top 1000 porte veloci
- `sudo nmap -sV -sC -p <porte_aperte> <target>` — Version + default scripts
- `sudo nmap -sU --top-ports 200 <target>` — UDP top 200
- `sudo nmap -O <target>` — OS detection
- `sudo nmap --script vuln -p <porte> <target>` — Vulnerability scripts
- `sudo nmap --script exploit <target>` — Exploit scripts (⚠ aggressivo, warning obbligatorio)
- `sudo nmap -f <target>` — Fragmented packets (firewall evasion)
- `sudo nmap -D RND:10 <target>` — Decoy scan (evasion)
- `sudo nmap -sN <target>` — NULL scan (stealth)
- `sudo nmap -sF <target>` — FIN scan (stealth)
- `sudo nmap -sX <target>` — Xmas scan (stealth)
- `sudo nmap -sA <target>` — ACK scan (firewall mapping)
- `sudo nmap -oX scan.xml <target>` — Output XML per parsing automatico

NETWORK:

- `traceroute <target>`
- `sudo traceroute -I <target>` — ICMP traceroute
- `ping -c 4 <target>`
- `sudo arp-scan --localnet` — Host discovery rete locale
- `sudo netdiscover -r <subnet>` — ARP discovery subnet
- `fping -a -g <subnet>` — Ping sweep subnet

SERVICE ENUM:

- `nc -nv <target> <porta>` — Banner grabbing manuale
- `sslscan <target>:<porta>` — SSL/TLS analysis
- `openssl s_client -connect <target>:443` — Certificato manuale
- `enum4linux -a <target>` — SMB/NetBIOS enumeration
- `smbclient -L //<target>` — SMB shares
- `rpcclient -U "" <target>` — RPC null session
- `snmpwalk -c public -v1 <target>` — SNMP v1
- `snmpwalk -c public -v2c <target>` — SNMP v2c
- `onesixtyone <target> public` — SNMP community bruteforce
- `smtp-user-enum -M VRFY -U users.txt -t <target>` — SMTP user enum

**Logica condizionale:**

- SYN scan non trova porte → suggerisce automaticamente UDP scan e stealth scan
- Trova porta 445 → aggiunge automaticamente enum4linux e smbclient al preview
- Trova porta 443 → aggiunge sslscan
- Trova porta 161 → aggiunge snmpwalk
- Nessun risultato con scan standard → suggerisce evasion techniques

---

### 2. Modulo OSINT

OSINT passivo completo. Non contatta direttamente il target in modo aggressivo. Usa API gratuite e tool locali.

**Lookup base:**

- `whois <target>` — Registrar, ASN, contatti, date
- `host <target>` — DNS resolution base
- `dig <target> ANY` — Tutti i record DNS
- `dig <target> MX` — Mail server
- `dig <target> TXT` — Record TXT (SPF, DKIM, verifica dominio)
- `dig <target> NS` — Nameserver
- `dig -x <ip>` — Reverse DNS
- `nslookup <target>` — Alternative DNS lookup

**Subdomain enumeration:**

- `amass enum -d <domain>` — Subdomain enum passivo
- `subfinder -d <domain>` — Subdomain finder
- `assetfinder <domain>` — Asset discovery
- crt.sh API lookup (HTTP request a `https://crt.sh/?q=<domain>&output=json`)
- `dnsenum <domain>` — DNS enumeration + zone transfer attempt
- `dnsrecon -d <domain>` — DNS recon completo
- `fierce --domain <domain>` — DNS bruteforce

**Network info:**

- `curl ipinfo.io/<ip>` — Geolocalizzazione, ASN, ISP
- Shodan free tier API — Host info, porte, banner, CVE note
- BGP lookup via API (bgpview.io, gratuita) — ASN, prefissi, peer
- `geoiplookup <ip>` — Geolocalizzazione locale

**Web fingerprinting:**

- `curl -I <target>` — Header HTTP analysis
- `whatweb <target>` — Technology detection
- `wafw00f <target>` — WAF detection
- Favicon hash lookup (calcola MD5 del favicon, cerca su Shodan)
- `nikto -h <target>` — Web server misconfiguration scan

**Certificate analysis:**

- `openssl s_client -connect <target>:443 | openssl x509 -noout -text` — Cert completo
- crt.sh per certificati storici → altri domini sullo stesso cert → subdomain discovery

**Storico e diff:**

- Ogni scan OSINT viene salvato in `data/sessions/` con timestamp
- Comando `osint diff <data1> <data2>` mostra cosa è cambiato tra due scan

---

### 3. Modulo WEB

Enumeration e attack surface web.

**Directory/File bruteforce:**

- `gobuster dir -u <url> -w /usr/share/wordlists/dirb/common.txt`
- `gobuster dir -u <url> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
- `gobuster dir -u <url> -w <wordlist> -x php,html,txt,js,bak`
- `gobuster dns -d <domain> -w /usr/share/wordlists/subdomains.txt`
- `gobuster vhost -u <url> -w <wordlist>` — Virtual host discovery
- `dirb <url>` — Alternative a Gobuster
- `feroxbuster -u <url> -w <wordlist>` — Recursive bruteforce

**Web vulnerability scanning:**

- `nikto -h <target>` — Misconfiguration, header issues, old software
- `sqlmap -u <url> --forms --batch` — SQL injection automatico (⚠ aggressivo)
- `sqlmap -u <url> --dbs` — Database enumeration
- `sqlmap -u <url> -D <db> --tables` — Table enumeration
- `wfuzz -c -w <wordlist> <url>/FUZZ` — Parameter fuzzing
- `ffuf -w <wordlist> -u <url>/FUZZ` — Fast fuzzing

**Manual recon:**

- `curl -I <url>` — Headers
- `curl -L <url>` — Follow redirects
- `curl -X OPTIONS <url>` — Allowed methods
- `wget --spider <url>` — Link crawling

**Note implementative:**

- SQLmap e wfuzz hanno warning ⚠ AGGRESSIVO nel preview con conferma obbligatoria separata
- Wordlist path sono quelli standard di Kali, con fallback su path custom configurabile

---

### 4. Modulo BRUTE

Brute force controllato.

**Hydra:**

- `hydra -l <user> -P <wordlist> <target> ssh`
- `hydra -L <users> -P <wordlist> <target> ftp`
- `hydra -l <user> -P <wordlist> <target> http-post-form "<path>:<params>:<fail_string>"`
- `hydra -l <user> -P <wordlist> <target> smb`
- `hydra -l <user> -P <wordlist> <target> rdp`
- `hydra -l <user> -P <wordlist> <target> mysql`
- `hydra -l <user> -P <wordlist> <target> postgresql`
- `hydra -t 4 ...` — Thread ridotti per stealth

**Medusa (alternativa):**

- `medusa -h <target> -u <user> -P <wordlist> -M ssh`

**Password cracking:**

- `john --wordlist=<wordlist> <hash_file>` — John the Ripper
- `hashcat -m <mode> <hash_file> <wordlist>` — GPU cracking

**Note implementative:**

- Warning ⚠ AGGRESSIVO obbligatorio per tutti i comandi brute
- Il modulo chiede esplicitamente: target, servizio, username/lista, wordlist
- Wordlist di default: `/usr/share/wordlists/rockyou.txt` (standard Kali)
- Mostra sempre il comando completo nel preview prima di eseguire

---

### 5. Modulo EXPLOIT

Wrapper Metasploit + correlazione CVE automatica + Exploitability Score composito.

**Flusso:**

1. Legge i risultati del modulo Scan dalla sessione corrente
2. Interroga NVD API (gratuita) con versioni software trovate
3. Interroga ExploitDB API (gratuita) per exploit pubblici
4. Cerca moduli Metasploit corrispondenti via `searchsploit`
5. Calcola Exploitability Score composito per ogni vulnerabilità
6. Presenta ranked list ordinata per score reale, non solo CVSS
7. L'operatore sceglie quale lanciare → genera comando MSF pronto nel preview

**Exploitability Score composito (0-100):**

Il CVSS da solo non basta — un CVE con score 9.8 può essere inutilizzabile in pratica. Lo score composito considera:

|Fattore|Peso|Logica|
|---|---|---|
|CVSS base score|30%|Fonte NVD|
|Exploit pubblico su ExploitDB|+20 punti|Disponibile = più facile|
|Modulo Metasploit pronto|+25 punti|MSF = un comando solo|
|PoC su GitHub pubblico|+10 punti|Verificato funzionante|
|Richiede autenticazione|-20 punti|Più difficile da sfruttare|
|Solo accesso locale (non remoto)|-25 punti|Non sfruttabile da remoto|
|CVE recente < 6 mesi|+10 punti|Patch non ancora diffusa|
|Versione software confermata esatta|+15 punti|Match preciso = alta affidabilità|

**Output esempio:**

```
RANKED ATTACK SURFACE — 10.0.0.1
════════════════════════════════════════════════════════════════
#1  porta 21 — vsftpd 2.3.4
    CVE-2011-2523 | CVSS: 10.0 | CRITICAL
    Exploit: EDB-17491 ✓  |  MSF: exploit/unix/ftp/vsftpd_234_backdoor ✓
    Remoto: sì  |  Auth richiesta: no  |  PoC pubblico: sì
    ┌─ EXPLOITABILITY SCORE ──────────────────┐
    │  ████████████████████████████████  98/100 │
    └─────────────────────────────────────────┘

#2  porta 445 — Samba 3.0.20
    CVE-2007-2447 | CVSS: 9.3 | CRITICAL
    MSF: exploit/multi/samba/usermap_script ✓
    ┌─ EXPLOITABILITY SCORE ──────────────────┐
    │  █████████████████████████████░░░  91/100 │
    └─────────────────────────────────────────┘

#3  porta 80 — Apache 2.2.8
    CVE-2017-7679 | CVSS: 7.5 | HIGH
    Nessun modulo MSF  |  PoC: no
    ┌─ EXPLOITABILITY SCORE ──────────────────┐
    │  █████████████░░░░░░░░░░░░░░░░░░  42/100 │
    └─────────────────────────────────────────┘
```

**Comandi Metasploit gestiti:**

- `msfconsole -x "use <module>; set RHOSTS <target>; set LHOST <local>; run"`
- `searchsploit <software> <version>` — ExploitDB locale search

---

### 5b. Modulo PAYLOAD

Generazione payload intelligente. Legge automaticamente OS, architettura e porte dalla sessione corrente — non serve reinserire niente a mano.

**Flusso:**

```
[phantom] > use payload

[payload:10.0.0.1] > generate

[+] Dati sessione rilevati automaticamente:
    OS:   Linux x86_64 (Ubuntu 20.04)
    IP:   10.0.0.1
    LHOST rilevato: 192.168.1.10

  Tipo payload:
  [1] Reverse shell TCP
  [2] Bind shell TCP
  [3] Meterpreter reverse TCP
  [4] Meterpreter reverse HTTPS

  Formato output:
  [1] ELF (Linux binary)
  [2] Python
  [3] Bash one-liner
  [4] PHP
  [5] PowerShell (se target Windows)

  LPORT [4444] > _

[+] Comando generato:
    msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f elf -o shell.elf

  Cosa vuoi fare?
  [1] Esegui + avvia listener automatico in background
  [2] Mostrami solo il comando — lo eseguo manualmente
  [3] Modifica il comando prima di eseguire
```

L'opzione 1 genera il payload, avvia automaticamente il listener (modulo Handler) in background, e notifica quando arriva una connessione.

---

### 5c. Modulo HANDLER

Listener per reverse shell. Gestisce connessioni in entrata da payload generati con il modulo Payload.

```
[handler] > listen --port 4444 --type tcp

[+] Listener avviato su 0.0.0.0:4444
[+] In attesa di connessione...

[!] Connessione ricevuta da 10.0.0.1:52341
[+] Shell attiva — digita comandi o 'background' per mettere in background
```

Supporta più sessioni in background simultanee. `sessions list` per vederle, `sessions interact <n>` per riprenderne una.

---

### 5d. Modulo PIVOT

Helper per port forwarding e pivoting. Genera i comandi corretti senza doverli ricordare a memoria.

```
[pivot] > setup

  Tipo di tunnel:
  [1] SSH local forward (esponi porta remota in locale)
  [2] SSH remote forward (esponi porta locale sul target)
  [3] SSH dynamic (SOCKS proxy)
  [4] Chisel (quando SSH non disponibile)

  [+] Compilazione guidata parametri...
  [+] Comando generato e mostrato nel preview
```

---

### 6. Modulo ANALYZER

Analisi pcap da Wireshark export.

**Input:** file `.pcap` o `.pcapng` **Libreria:** `scapy` per parsing

**Analisi automatica:**

- Credenziali in chiaro (HTTP Basic Auth, FTP login, Telnet)
- Sessioni HTTP con parametri (GET/POST con dati sensibili)
- DNS queries — domini contattati, tunneling DNS anomalo
- ARP anomali — possibile ARP poisoning
- Porte inusuali — traffico su porte non standard
- Scan patterns — sequenze che indicano port scanning in entrata
- Volume anomalo per IP — possibile DoS o exfiltration
- Protocolli non cifrati su porte che dovrebbero essere cifrate

**Output:** lista prioritizzata per rilevanza, non tutti i packet

---

### 7. Modulo REPORT

Genera report completo della sessione.

**Formati:** PDF (con `reportlab`), HTML, JSON **Contenuto:** target, modalità usata, timestamp, tutti i comandi eseguiti, output rilevante, CVE trovate, screenshot ASCII dell'output principale **Comando:** `export pdf report_2024_01_15.pdf`

---

## Modulo WORDLIST MANAGER

Centralizza l'accesso a tutte le wordlist su Kali, sparse in directory diverse. Le indicizza una volta sola all'avvio e le rende accessibili per nome semplice da qualsiasi modulo.

**Directory scansionate automaticamente:**

- `/usr/share/wordlists/`
- `/usr/share/seclists/`
- `/usr/share/dirb/wordlists/`
- `/usr/share/dirbuster/wordlists/`
- Path custom configurabile dall'utente

**Comandi:**

```
wordlists list                  # Lista tutte le wordlist per categoria
wordlists list passwords        # Filtra per categoria
wordlists use rockyou           # Imposta wordlist attiva per la sessione
wordlists use <path_custom>     # Imposta wordlist da path assoluto
wordlists info rockyou          # Mostra path, dimensione, numero di entries
wordlists search <keyword>      # Cerca wordlist per nome
```

**Output esempio:**

```
[phantom] > wordlists list

  PASSWORDS
  rockyou.txt              14,344,391 entries   /usr/share/wordlists/rockyou.txt
  fasttrack.txt                   222 entries   /usr/share/wordlists/fasttrack.txt
  unix-passwords.txt            1,009 entries   /usr/share/wordlists/unix-passwords.txt

  DIRECTORIES
  common.txt                    4,614 entries   /usr/share/wordlists/dirb/common.txt
  big.txt                      20,469 entries   /usr/share/wordlists/dirb/big.txt
  directory-list-2.3-medium   220,560 entries   /usr/share/dirbuster/...

  SUBDOMAINS
  subdomains-top1million      1,000,000 entries  /usr/share/seclists/...
  dns-jhaddix.txt               273,123 entries  /usr/share/seclists/...

  USERNAMES
  top-usernames-shortlist.txt        17 entries  /usr/share/seclists/...
```

Una volta impostata con `wordlists use`, tutti i moduli (Brute, Web, OSINT) la usano automaticamente senza che tu debba reinserire il path.

---

## Scope Management

Previene esecuzione accidentale di comandi su IP fuori scope.

```
[phantom] > set scope 10.0.0.0/24,10.0.1.5

[phantom] > set target 192.168.1.1
[!] WARNING: 192.168.1.1 è fuori dallo scope definito.
    Scope attuale: 10.0.0.0/24, 10.0.1.5
    Procedere comunque? [y/N]
```

Ogni comando che viene eseguito su un IP viene verificato contro lo scope prima dell'esecuzione. Implementato in `scope.py` come validatore chiamato da `executor.py`.

---

## Session Persistence

Le sessioni vengono salvate su disco in `data/sessions/` come JSON. Contengono tutto: target, scope, modalità, risultati di ogni modulo, note, comandi eseguiti, timestamp.

```
[phantom] > save-session engagement_acme_day1
[+] Sessione salvata: data/sessions/engagement_acme_day1.json

# Giorno dopo
$ phantom
[phantom] > load-session engagement_acme_day1
[+] Sessione caricata:
    Target: 10.0.0.1
    Scope: 10.0.0.0/24
    Scan completato: 22, 80, 443, 8080
    OSINT completato
    Note: 3 note salvate
    Ultimo accesso: 2024-01-14 18:32

[phantom] > use exploit   # riprendi da dove avevi lasciato
```

All'uscita con `exit`, Phantom chiede automaticamente se salvare la sessione corrente.

---

## Note Inline

```
[scan:10.0.0.1] > back
[phantom] > note "porta 8080 risponde con X-Powered-By: PHP/5.4 — versione molto vecchia, cercare CVE"
[+] Nota aggiunta (14:23:07)

[phantom] > notes

  SESSIONE NOTES — 10.0.0.1
  ─────────────────────────────────────────────────
  [1] 14:21:02  Scan completato — porte aperte: 22, 80, 443, 8080
  [2] 14:23:07  porta 8080 risponde con X-Powered-By: PHP/5.4 — versione molto vecchia
  [3] 14:45:11  enum4linux ha trovato share SMB aperta: //10.0.0.1/backup
```

Le note finiscono automaticamente nel report finale con il loro timestamp.

---

## Dipendenze Python

```
# requirements.txt
rich>=13.0.0          # Output colorato, tabelle, progress bar
requests>=2.31.0      # HTTP requests per API
python-nmap>=0.7.1    # Wrapper Nmap
scapy>=2.5.0          # Packet analysis per modulo analyzer
reportlab>=4.0.0      # Generazione PDF per report
python-whois>=0.8.0   # Whois lookup
dnspython>=2.4.0      # DNS queries avanzate
```

**Tool di sistema richiesti (presenti su Kali di default):** nmap, gobuster, hydra, sqlmap, metasploit-framework, nikto, enum4linux, sslscan, traceroute, arp-scan, netdiscover, amass, subfinder, whatweb, wafw00f, feroxbuster, ffuf, wfuzz, john, hashcat, medusa, dirb, dnsenum, dnsrecon, fierce

---

## Installazione

```bash
git clone https://github.com/Terminalkid09/phantom
cd phantom
pip install -e .
phantom
```

`setup.py` registra `phantom` come comando globale nel PATH.

---

## Sessione esempio completa

```
$ phantom

  ██████╗ ██╗  ██╗ █████╗ ███╗  ██╗████████╗ ██████╗ ███╗  ███╗
  ██╔══██╗██║  ██║██╔══██╗████╗ ██║╚══██╔══╝██╔═══██╗████╗████║
  ██████╔╝███████║███████║██╔██╗██║   ██║   ██║   ██║██╔████╔██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚████║   ██║   ██║   ██║██║╚██╔╝██║
  ██║     ██║  ██║██║  ██║██║ ╚███║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
  v1.0.0 — Offensive Security Framework

[phantom] > set target 10.0.0.5
[+] Target impostato: 10.0.0.5

[phantom] > set mode recon
[+] Modalità: recon (exploit disabilitati)

[phantom] > use scan
[scan:10.0.0.5] > run
[scan:10.0.0.5] > preview

  ── NMAP ──────────────────────────────────────
  [1] sudo nmap -sS -p- --min-rate 5000 10.0.0.5
  [2] sudo nmap -sV -sC -p 22,80,443 10.0.0.5
  ...

  edit [n], remove [n], add, run-group [nome], run-all > run-all

[+] Esecuzione NMAP...
[+] Porte trovate: 22, 80, 443, 8080
[!] Porta 445 non trovata — vuoi aggiungere SMB scan? [y/N]

[scan:10.0.0.5] > back

[phantom] > use osint
[osint:10.0.0.5] > run
...

[phantom] > export pdf report_10.0.0.5.pdf
[+] Report generato: report_10.0.0.5.pdf
```

---

## Ordine di sviluppo consigliato

1. **Shell core + Session + Scope + Notes** — fondamenta di tutto
2. **Preview system + Executor** — il differenziale principale
3. **Session persistence** — save/load sessioni su disco
4. **Wordlist Manager** — utile da subito per tutti i moduli successivi
5. **Modulo Scan** — primo modulo reale, il più usato
6. **Modulo OSINT** — secondo per impatto, tutto gratuito
7. **Modulo Web** — Gobuster + Nikto + SQLmap
8. **Modulo Brute** — Hydra + John
9. **Modulo Exploit + Exploitability Score** — CVE correlation + MSF wrapper
10. **Modulo Payload + Handler** — generazione payload + listener integrato
11. **Modulo Pivot** — port forwarding helper
12. **Modulo Analyzer** — pcap analysis con scapy
13. **Modulo Report** — PDF/HTML generation
14. **Polish** — README professionale, demo GIF, documentazione da tool open source vero

**Regola ferrea:** ogni modulo deve essere funzionante e testato prima di passare al successivo. Meglio 5 moduli solidi che 13 moduli rotti.

---

## Note per AI assistant

- Il progetto è Python puro, nessun framework web
- Usa `cmd.Cmd` per la shell interattiva, non librerie terze parti per questo
- Usa `rich` per tutto l'output — niente `print()` plain
- Usa `subprocess.run()` per eseguire tool di sistema, cattura stdout/stderr
- Lo stato globale vive in `Session` (singleton), accessibile da tutti i moduli
- Ogni modulo estende `BaseModule` con metodi `preview()`, `run()`, `configure()`
- I comandi aggressivi (exploit, brute, SQLmap) hanno sempre warning e conferma separata
- Nessuna esecuzione automatica senza approvazione esplicita dell'operatore
- Il codice deve essere pulito, modulare, commentato essenzialmente — niente noise