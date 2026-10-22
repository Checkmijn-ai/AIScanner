"""Maakt de voorbeeldrapporten op de site uit twee echte rapporten (rapport.json uit .checkmijn/ van een project):
de eerste scan en de scan na herstel. De score wordt opnieuw berekend op de huidige schaal (zelfscan: C tot G).

Gebruik: python tools/voorbeeldrapport.py VOOR.json NA.json "Naam van de app"
Schrijft platform/static/voorbeeldrapport.html (voor) en platform/static/voorbeeldrapport-na.html (na).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from aiscan.core import Finding, Result  # noqa: E402
from aiscan.report import write_html  # noqa: E402
from aiscan.score import bereken  # noqa: E402

BALK = ('<div style="background:#15203a;color:#fff;padding:12px 16px;font:14px/1.5 -apple-system,\'Segoe UI\',sans-serif">'
        '<div style="max-width:1040px;margin:0 auto;display:flex;gap:10px 18px;flex-wrap:wrap;align-items:center">'
        '<b>Voorbeeldrapport {nr} van 2 · {wat}</b><span style="opacity:.8">Echt rapport van {app}, een app gebouwd met AI, '
        'gescand op {datum}.</span><a href="{ander}" style="color:#7fe0d8;font-weight:600">{andertekst} →</a>'
        '<a href="/" style="color:#fff;opacity:.8;margin-left:auto">checkmijn.ai</a></div></div>')


def maak(src: Path, out: Path, app: str, nr: int, wat: str, ander: str, andertekst: str) -> str:
    d = json.loads(src.read_text(encoding="utf-8"))
    results = []
    for c in d["checks"]:
        r = Result(c["id"], c["status"], c.get("reden", ""), info=c.get("info", []))
        for f in c["bevindingen"]:
            r.add(Finding(f["check"], f["ernst"], f["titel"], f.get("bestand", ""), f.get("regel", 0), f.get("bewijs", ""),
                          f.get("bevestigen", False)))
        results.append((c, r))
    s = d["samenvatting"]
    s.update({"soort": "Zelfscan", "klant": app, "score": bereken(results, 1, deel=False)})
    write_html(out, s, results)
    html = out.read_text(encoding="utf-8")
    balk = BALK.format(nr=nr, wat=wat.format(letter=s["score"]["letter"]), app=app, datum=s["datum"], ander=ander, andertekst=andertekst)
    out.write_text(html.replace("<body>", "<body>" + balk, 1), encoding="utf-8")
    return s["score"]["letter"]


if __name__ == "__main__":
    voor, na, app = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    st = ROOT / "platform" / "static"
    a = maak(voor, st / "voorbeeldrapport.html", app, 1, "eerste scan: {letter}", "/voorbeeldrapport/na", "Na herstel")
    b = maak(na, st / "voorbeeldrapport-na.html", app, 2, "na herstel: {letter}", "/voorbeeldrapport", "Eerste scan")
    print(f"{app}: {a} → {b}")
