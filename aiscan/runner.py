"""Draait de checks en maakt de samenvatting."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import traceback
from pathlib import Path

import yaml

from . import __version__
from .checks import load_all
from .core import ERNST_ORDE, Project, Result, to_dict
from .score import bereken

DATA = Path(__file__).resolve().parent / "data"

WETTEN = [
    ("CRA (Cyber Resilience Act)", r"\bCRA\b", "Alleen van toepassing als de software als product op de markt komt; niet voor SaaS zonder bijhorend product of interne tools."),
    ("AVG (GDPR)", r"\bAVG\b", "Technische kant; geen oordeel over de rechtsgrond van de verwerking."),
    ("AI Act", r"AI Act", "Transparantie en robuustheid; geen conformiteitsbeoordeling voor hoog-risico-AI."),
    ("ePrivacyrichtlijn (cookies)", r"ePrivacy", ""),
    ("NIS2", r"NIS2", "NIS2 verplicht organisaties, geen software: bewijs voor de leveranciersbeoordeling."),
]
NORMEN = [
    ("OWASP Top 10:2025", r"\bA\d\d:2025|Top 10:2025"), ("OWASP ASVS 5.0", r"ASVS"), ("OWASP API Security", r"\bAPI\d"),
    ("OWASP voor AI en agents", r"LLM\d|Agentic|AISVS"), ("OWASP MASVS", r"MASVS"), ("ISO/IEC 27002", r"27002"),
    ("ISO/IEC 25010, 25023, 5055", r"25010|25023|5055"), ("ISO/IEC 42001", r"42001"),
    ("SLSA, OpenSSF, NIST SSDF", r"SLSA|OpenSSF|800-218"), ("CIS Benchmarks", r"CIS "), ("Cryptografie (NIST, BSI)", r"800-52|BSI TR"),
]


def load_checks(niveau: int):
    cs = yaml.safe_load((DATA / "checks.yaml").read_text())
    return [c for c in cs if c.get("status", "actief") == "actief"]  # deze versie bevat de 45 scans van niveau 1


def ruleset_hash():
    h = hashlib.sha256()
    for p in sorted(DATA.glob("*")):
        h.update(p.name.encode())
        h.update(p.read_bytes())
    return h.hexdigest()[:12]


def run(target: str, niveau: int = 1, url=None, offline=True, github_token=None, only=None, log=print):
    checks = load_checks(niveau)
    if only:
        checks = [c for c in checks if c["id"] in only]
    registry = load_all()
    proj = Project(target, offline=offline, github_token=github_token, url=url)
    results = []
    for c in checks:
        fn = registry.get(c["id"])
        if not fn:
            res = Result(c["id"], "Niet gescand", "Nog geen automatische controle in deze versie.")
        else:
            try:
                res = fn(proj, c)
            except Exception as e:  # een fout in één check mag de scan niet stoppen
                res = Result(c["id"], "Niet gescand", f"Fout in de scanner: {type(e).__name__}: {e}")
                res.info.append(traceback.format_exc(limit=2))
        # dubbels weg, sorteren op ernst
        seen, uniq = set(), []
        for f in res.findings:
            if f.key() not in seen:
                seen.add(f.key())
                uniq.append(f)
        res.findings = sorted(uniq, key=lambda f: (-ERNST_ORDE.get(f.ernst, 0), f.bestand, f.regel))
        if res.status == "Gehaald" and any(f.ernst != "Info" for f in res.findings):
            res.status = "Bevinding"
        log(f"  {c['id']:5} {res.status:20} {len(res.findings)} bevinding(en)")
        results.append((c, res))
    return proj, results


def summarize(proj, results, meta: dict):
    status = {"Gehaald": 0, "Bevinding": 0, "Niet van toepassing": 0, "Niet gescand": 0}
    ernst = {"Kritiek": 0, "Hoog": 0, "Middel": 0, "Laag": 0}
    bevestigen = 0
    for c, r in results:
        status[r.status] = status.get(r.status, 0) + 1
        for f in r.findings:
            if f.ernst in ernst:
                ernst[f.ernst] += 1
            bevestigen += int(f.bevestigen)
    gescand = status["Gehaald"] + status["Bevinding"]

    def per(rx):
        rows = [(c, r) for c, r in results if re.search(rx, c["normen"])]
        return {"checks": len(rows),
                "gehaald": sum(r.status == "Gehaald" for _, r in rows),
                "bevinding": sum(r.status == "Bevinding" for _, r in rows),
                "open": sum(r.status in ("Niet gescand",) for _, r in rows),
                "nvt": sum(r.status == "Niet van toepassing" for _, r in rows),
                "ids": [c["id"] for c, _ in rows]}
    wetten = [{"naam": n, "noot": noot, **per(rx)} for n, rx, noot in WETTEN]
    normen = [{"naam": n, **per(rx)} for n, rx in NORMEN]
    wetten = [w for w in wetten if w["checks"]]
    normen = [n for n in normen if n["checks"]]
    open_hoog = ernst["Kritiek"] + ernst["Hoog"]
    return {
        **meta,
        "scanner": f"aiscan {__version__}",
        "regelset": ruleset_hash(),
        "datum": dt.date.today().isoformat(),
        "commit": proj.git_head(),
        "status": status, "ernst": ernst, "gescand": gescand, "totaal": len(results), "bevestigen": bevestigen,
        "uitslag": "Geen open kritieke of hoge bevindingen" if open_hoog == 0 else f"{open_hoog} kritieke of hoge bevinding(en) open",
        "ai": getattr(proj, "ai", {"gebruikt": None}),
        "wetten": wetten, "normen": normen,
        "score": bereken(results, meta.get("niveau", 1), deel=len(results) < len(load_checks(1))),
        "talen": sorted(proj.languages),
        "bestanden": len(proj.files),
    }


def to_json(summary, results):
    return {"samenvatting": summary,
            "checks": [{**{k: c[k] for k in ("id", "domein", "scan", "normen", "methode", "ernst")},
                        "status": r.status, "reden": r.reden, "info": r.info,
                        "bevindingen": [to_dict(f) for f in r.findings]} for c, r in results]}
