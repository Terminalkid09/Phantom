"""synth.py — deterministic, schema-valid seed data for the thin phases.

Two phases have almost no artifacts in a normal checkout: ``osint`` (identity
edges only exist when a run explored them) and ``social`` (a draft only exists
when a campaign was built). ``scan_parse`` is thin too because checkpoints
store the command, not the tool output.

This module does not invent facts about a target. It writes small, clearly
labelled examples of the BEHAVIOUR each phase must learn (a confidence for a
pair, a short opener with no link, a port table from real nmap-shaped text).
Every label is validated against ``phantom.automation.ai.schemas`` and skipped
if the runtime would refuse it, so synthetic data can never teach a format the
model cannot use.

    python -m training.synth --out training/data/synth

The output is deterministic: same file, same bytes, on every run.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

from phantom.automation.ai import schemas
from training.build_dataset import _messages


def _filler(i: int) -> Dict[str, str]:
    names = [
        ("luca.bianchi", "Luca Bianchi", "Milano"),
        ("giulia.ferrari", "Giulia Ferrari", "Torino"),
        ("marco.conti", "Marco Conti", "Bologna"),
        ("sara.romano", "Sara Romano", "Roma"),
        ("davide.greco", "Davide Greco", "Napoli"),
        ("elena.ricci", "Elena Ricci", "Firenze"),
        ("andrea.marino", "Andrea Marino", "Genova"),
        ("chiara.gallo", "Chiara Gallo", "Verona"),
        ("paolo.esposito", "Paolo Esposito", "Bari"),
        ("martina.lombardi", "Martina Lombardi", "Padova"),
    ]
    handle, name, city = names[i % len(names)]
    return {"handle": handle, "name": name, "city": city}


def osint_records() -> List[dict]:
    platforms = ["github", "x", "telegram", "instagram"]
    rows: List[dict] = []
    for i in range(28):                        # same person, strong signals
        who = _filler(i)
        primary = {"platform": platforms[i % 4], "handle": who["handle"],
                   "bio": f"{who['city']} · backend", "avatar_hash": f"{i:016x}"}
        candidate = {"platform": platforms[(i + 1) % 4],
                     "handle": who["handle"],
                     "bio": f"{who['city']} · backend",
                     "avatar_hash": f"{i:016x}"}
        rows.append(_messages("osint", {"primary": primary,
                                        "candidate": candidate}, {
            "links": [{"handle": who["handle"],
                       "platform": candidate["platform"], "confidence": 0.85,
                       "signals": ["same_handle", "same_avatar", "same_bio"]}],
            "notes": "three independent signals agree"}))
    for i in range(12):                        # one weak signal only
        who = _filler(i + 3)
        primary = {"platform": "github", "handle": who["handle"],
                   "bio": "photographer"}
        candidate = {"platform": "instagram", "handle": who["handle"],
                     "bio": "travel and coffee"}
        rows.append(_messages("osint", {"primary": primary,
                                        "candidate": candidate}, {
            "links": [{"handle": who["handle"],
                       "platform": candidate["platform"], "confidence": 0.55,
                       "signals": ["same_handle"]}],
            "notes": "a shared handle alone is not identity proof"}))
    for i in range(20):                        # different people
        a, b = _filler(i), _filler(i + 5)
        primary = {"platform": "x", "handle": a["handle"],
                   "bio": f"{a['city']} · designer",
                   "avatar_hash": f"{i + 100:016x}"}
        candidate = {"platform": "instagram", "handle": b["handle"],
                     "bio": f"{b['city']} · backend",
                     "avatar_hash": f"{i + 200:016x}"}
        rows.append(_messages("osint", {"primary": primary,
                                        "candidate": candidate}, {
            "links": [], "notes": "no shared signal: different handle, bio "
                                  "and avatar"}))
    return rows


_SOCIAL = [
    ("dm", "shared_interest", "it", "fotografia",
     "Ho visto il tuo scatto alla Darsena, la luce di quella sera era "
     "davvero particolare. Scatti ancora con il 35mm o sei passato a "
     "qualcos'altro?"),
    ("dm", "shared_interest", "it", "corsa",
     "Ho letto che fai la mezza maratona: sto cercando un percorso per "
     "allenarmi in città. Tu quale usi di solito?"),
    ("dm", "shared_interest", "it", "musica",
     "Ho ascoltato la playlist che hai condiviso, c'è un pezzo che non "
     "conoscevo. Chi è il gruppo?"),
    ("dm", "shared_interest", "it", "cucina",
     "Quella ricetta del venerdì sembrava semplice ma buona. Usi il forno "
     "statico o ventilato?"),
    ("dm", "shared_interest", "it", "viaggi",
     "Hai pubblicato le foto di Lisbona: ci vado il mese prossimo. Quale "
     "quartiere mi consigli per dormire?"),
    ("dm", "shared_interest", "it", "libri",
     "Ho visto il libro sul comodino nella tua storia. Vale la pena? Sto "
     "cercando qualcosa di simile."),
    ("dm", "shared_interest", "it", "bici",
     "Hai fatto il giro del lago in bici? Vorrei provarlo, ma non so da "
     "dove partire. Tu da quale paese sei partito?"),
    ("dm", "shared_interest", "it", "calcio",
     "Ho visto la foto allo stadio: eri in curva? Non ci sono mai stato, "
     "com'è l'atmosfera?"),
    ("dm", "event_invite", "it", "Milano",
     "C'è la mostra di fotografia a Milano fino a domenica. Ci vai? Se "
     "vuoi ci becchiamo lì, mi incuriosisce il piano di sopra."),
    ("dm", "event_invite", "it", "Torino",
     "Sabato c'è il mercato del libro usato in piazza. Tu ci passi? Io "
     "cerco i cataloghi di architettura."),
    ("dm", "event_invite", "it", "Bologna",
     "Giovedì fanno la serata aperta al circolo di fotografia. Ti va di "
     "passare? Non conosco nessuno lì."),
    ("dm", "event_invite", "it", "Roma",
     "Domenica c'è la camminata al parco degli acquedotti, partono alle "
     "nove. Tu ti unisci?"),
    ("dm", "shared_interest", "en", "cycling",
     "Saw your ride along the river last weekend. I'm looking for a "
     "quiet route on this side of town. Which one do you take?"),
    ("dm", "shared_interest", "en", "coffee",
     "Your post from the roastery made me curious. Do they do a filter "
     "brew, or only espresso?"),
    ("dm", "shared_interest", "en", "photography",
     "The long exposure on your last shot is great. Did you use a tripod "
     "or just rest the camera on the wall?"),
    ("dm", "event_invite", "en", "Berlin",
     "There's a small print fair in Berlin this weekend. Are you going? "
     "I'm thinking of dropping by on Saturday."),
    ("dm", "event_invite", "en", "London",
     "The photo walk starts at the market at ten on Sunday. Fancy "
     "joining? I've never been to that part of the city."),
    ("dm", "shared_interest", "en", "running",
     "Saw your half marathon result, that's a strong pace. What does a "
     "normal training week look like for you?"),
]


def social_records() -> List[dict]:
    rows: List[dict] = []
    for channel, pretext, lang, topic, text in _SOCIAL:
        rows.append(_messages("social", {
            "channel": channel, "pretext": pretext,
            "context": {"language": lang, "interest": topic},
        }, {"text": text}))
    for i in range(8):                          # email-shaped, still no link
        who = _filler(i)
        rows.append(_messages("social", {
            "channel": "email", "pretext": "order_update",
            "context": {"language": "it", "order": f"44{i:02d}"},
        }, {"text": (f"Buongiorno {who['name']}, l'ordine {4400 + i} è "
                     f"partito oggi e arriva in due giorni lavorativi. "
                     f"Vuole che lo lasciamo al portiere?"),
            "subject": f"Ordine {4400 + i}: spedizione"}))
    return rows


_SCAN_OUTPUTS = [
    ("22/tcp open ssh OpenSSH 8.9p1 Ubuntu 3ubuntu0.6\n"
     "80/tcp open http nginx 1.24.0", [{"port": 22, "service": "ssh",
                                        "product": "OpenSSH",
                                        "version": "8.9p1"},
                                       {"port": 80, "service": "http",
                                        "product": "nginx",
                                        "version": "1.24.0"}]),
    ("443/tcp open ssl/http Apache httpd 2.4.57\n"
     "3306/tcp open mysql MySQL 8.0.35", [{"port": 443, "service": "http",
                                           "product": "Apache httpd",
                                           "version": "2.4.57"},
                                          {"port": 3306, "service": "mysql",
                                           "product": "MySQL",
                                           "version": "8.0.35"}]),
    ("21/tcp open ftp vsftpd 3.0.5\n"
     "22/tcp open ssh OpenSSH 8.2p1\n"
     "8080/tcp open http Jetty 9.4.50", [{"port": 21, "service": "ftp",
                                          "product": "vsftpd",
                                          "version": "3.0.5"},
                                         {"port": 22, "service": "ssh",
                                          "product": "OpenSSH",
                                          "version": "8.2p1"},
                                         {"port": 8080, "service": "http",
                                          "product": "Jetty",
                                          "version": "9.4.50"}]),
    ("53/tcp open domain dnsmasq 2.90\n"
     "445/tcp open microsoft-ds Samba 4.15.13", [{"port": 53,
                                                  "service": "domain",
                                                  "product": "dnsmasq",
                                                  "version": "2.90"},
                                                 {"port": 445,
                                                  "service": "microsoft-ds",
                                                  "product": "Samba",
                                                  "version": "4.15.13"}]),
    ("Not shown: 998 filtered tcp ports\n"
     "3389/tcp open ms-wbt-server Microsoft Terminal Services", [
         {"port": 3389, "service": "ms-wbt-server",
          "product": "Microsoft Terminal Services"}]),
    ("161/udp open snmp SNMPv3\n"
     "500/udp open isakmp", [{"port": 161, "service": "snmp"},
                             {"port": 500, "service": "isakmp"}]),
    ("All 1000 scanned ports on 10.0.0.5 are in ignored states.\n"
     "Not shown: 1000 filtered tcp ports", []),
    ("Nmap done: 1 IP address (1 host up) scanned in 2.31 seconds", []),
]


def scan_records() -> List[dict]:
    rows: List[dict] = []
    for i in range(36):
        output, findings = _SCAN_OUTPUTS[i % len(_SCAN_OUTPUTS)]
        rows.append(_messages("scan_parse", {"tool": "nmap",
                                            "output": output},
                              {"findings": findings, "notes": ""}))
    return rows


GENERATORS = {
    "osint": osint_records,
    "social": social_records,
    "scan_parse": scan_records,
}


def build(phase: str) -> List[dict]:
    rows = GENERATORS[phase]()
    clean: List[dict] = []
    for row in rows:
        label = json.loads(row["messages"][2]["content"])
        if schemas.validate(phase, label):
            continue
        clean.append({"phase": phase, "source": "synth", "label": "seed",
                      "messages": row["messages"]})
    return clean


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="training.synth")
    parser.add_argument("--out", default="training/data/synth")
    parser.add_argument("--phase", default="all",
                        choices=list(GENERATORS) + ["all"])
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    phases = list(GENERATORS) if args.phase == "all" else [args.phase]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for phase in phases:
        rows = build(phase)
        path = out / f"{phase}.jsonl"
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True,
                                        ensure_ascii=False) + "\n")
        if not args.quiet:
            print(f"{phase}: {len(rows)} seed record(s) -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
