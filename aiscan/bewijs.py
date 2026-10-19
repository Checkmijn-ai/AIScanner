"""Bewijsbestand: wat een scan aantoont, zonder broncode, bestandsnamen of geheimen.

Het bevat:
- welke scanner (versie, controlegetal van het pyz-bestand, regelset, stand van de lekkendatabank);
- de sessiecode (nonce) die de agent bij de start ophaalde, zodat een oude scan niet hergebruikt kan worden;
- welke code: het git-commit en een controlegetal over alle gescande bestanden;
- per check: status, zwaarste bevinding (zoals de score ze telt) en aantal bevindingen;
- de score.
Er staat geen regel code, geen pad en geen bevindingstekst in.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import sys
from pathlib import Path

from . import __version__
from .score import NAAM, effectief

FORMAAT = "aiscan-bewijs/1"


def scanner_sha256():
    """Controlegetal van het pyz-bestand waaruit de scanner draait (gezet door de bootstrap), anders None."""
    p = os.environ.get("AISCAN_PYZ")
    if p and Path(p).is_file():
        return hashlib.sha256(Path(p).read_bytes()).hexdigest()
    return None


def boom_hash(proj):
    """Controlegetal over de gescande bestanden: pad en inhoud, gesorteerd. Toont welke code gescand is, zonder ze prijs te geven."""
    h = hashlib.sha256()
    for p in sorted(proj.files, key=lambda x: proj.rel(x)):
        try:
            data = p.read_bytes()
        except OSError:
            continue
        h.update(proj.rel(p).encode() + b"\0" + hashlib.sha256(data).digest())
    return h.hexdigest()


def maak(proj, results, summary, nonce: str | None):
    from .checks.supply import advisories
    from .runner import ruleset_hash
    res = []
    for c, r in results:
        zw = max((effectief(f) for f in r.findings), default=None)
        res.append({"id": c["id"], "status": r.status, "zwaarste": NAAM[zw] if zw is not None else None,
                     "aantal": len(r.findings)})
    sc = summary["score"]
    return {
        "formaat": FORMAAT,
        "tijd": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "nonce": nonce,
        "scanner": {"versie": __version__, "sha256": scanner_sha256(), "regelset": ruleset_hash(),
                    "dagversie": os.environ.get("AISCAN_DAGVERSIE"),
                    "databank": advisories()["meta"].get("stand"), "python": sys.version.split()[0]},
        "project": {"naam": summary.get("app"), "commit": proj.git_head(), "boom_sha256": boom_hash(proj),
                    "bestanden": len(proj.files)},
        "niveau": summary.get("niveau", 1),
        "soort": "Zelfcontrole",
        "resultaten": res,
        "score": {"letter": sc["letter"], "dekking": sc["dekking"]},
        "ernst": summary["ernst"],
    }
