"""Catalogus van checks: vaste nummering, versies en changelog.

Regels voor de nummering:
- Een ID (bv. E-05) hoort voor altijd bij één controle. Een vervallen ID wordt nooit opnieuw gebruikt.
- Een nieuwe check krijgt het volgende vrije nummer in zijn domein, ook rekening houdend met alle ID's die in de
  volledige keuringsnorm (niveau 1 tot 4) al bestaan.
- Wijzigt de tekst, de normen of de standaardernst van een check, dan stijgt zijn versie (1, 2, 3 …).
- Elke wijziging komt in de changelog, met datum.

Gebruik:
  python platform/catalogus.py lijst
  python platform/catalogus.py controleer
  python platform/catalogus.py nieuw --domein E --scan "Beschrijving" --normen "OWASP ASVS 5.0" --ernst Hoog \
         --methode scan --module code --hint "Hoe je het herstelt"
  python platform/catalogus.py vervallen E-12 --reden "opgenomen in E-04"
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "aiscan" / "data"
CATALOGUS = DATA / "checks.yaml"
NORM_IDS = DATA / "norm_ids.json"
ERNST = ("Kritiek", "Hoog", "Middel", "Laag")
ID_RX = re.compile(r"^[A-Z]-\d{2}$")
PUBLIEK = ("id", "domein", "scan", "normen", "ernst", "methode", "sinds", "versie", "status")


def laad(pad: Path = CATALOGUS):
    return yaml.safe_load(pad.read_text())


def bewaar(checks, pad: Path = CATALOGUS):
    pad.write_text(yaml.safe_dump(checks, allow_unicode=True, sort_keys=False, width=200))


def controleer(checks):
    """Geeft een lijst van fouten; leeg = in orde."""
    fouten, gezien = [], set()
    for c in checks:
        cid = c.get("id", "")
        if not ID_RX.match(cid):
            fouten.append(f"{cid}: ongeldig formaat (verwacht bv. E-05)")
        if cid in gezien:
            fouten.append(f"{cid}: komt twee keer voor")
        gezien.add(cid)
        if c.get("ernst") not in ERNST:
            fouten.append(f"{cid}: ernst moet een van {ERNST} zijn")
        for veld in ("domein", "scan", "normen", "methode", "module", "hint"):
            if not c.get(veld):
                fouten.append(f"{cid}: veld '{veld}' ontbreekt")
        if c.get("status", "actief") not in ("actief", "vervallen"):
            fouten.append(f"{cid}: status moet actief of vervallen zijn")
    return fouten


def actief(checks):
    return [c for c in checks if c.get("status", "actief") == "actief"]


def volgend_id(checks, letter: str) -> str:
    gebruikt = {c["id"] for c in checks}
    try:
        gebruikt |= set(json.loads(NORM_IDS.read_text())["ids"])
    except Exception:
        pass
    nrs = [int(i.split("-")[1]) for i in gebruikt if re.match(rf"^{letter}-\d+$", i)]
    return f"{letter}-{(max(nrs) if nrs else 0) + 1:02d}"


def publiek(checks):
    """De catalogus zoals hij op de site staat: zonder interne velden."""
    rows = [{k: c.get(k) for k in PUBLIEK} for c in checks]
    blob = json.dumps(rows, sort_keys=True, ensure_ascii=False).encode()
    return {"aantal_actief": len(actief(checks)), "sha256": hashlib.sha256(blob).hexdigest(), "checks": rows}


def verschil(oud: list, nieuw: list, datum: str):
    """Changelog-regels tussen twee publieke catalogi."""
    o = {c["id"]: c for c in oud}
    n = {c["id"]: c for c in nieuw}
    regels = []
    for cid in sorted(n):
        if cid not in o:
            regels.append({"datum": datum, "id": cid, "wijziging": "toegevoegd", "scan": n[cid]["scan"]})
        elif n[cid].get("status") == "vervallen" and o[cid].get("status") != "vervallen":
            regels.append({"datum": datum, "id": cid, "wijziging": "vervallen"})
        elif n[cid].get("versie") != o[cid].get("versie"):
            regels.append({"datum": datum, "id": cid, "wijziging": f"versie {o[cid].get('versie')} → {n[cid].get('versie')}"})
    for cid in sorted(set(o) - set(n)):
        regels.append({"datum": datum, "id": cid, "wijziging": "verwijderd (niet toegestaan: gebruik 'vervallen')"})
    return regels


def main(argv=None):
    ap = argparse.ArgumentParser(description="Catalogus van checks beheren")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("lijst")
    sub.add_parser("controleer")
    n = sub.add_parser("nieuw")
    for veld in ("domein", "scan", "normen", "ernst", "methode", "module", "hint"):
        n.add_argument(f"--{veld}", required=True)
    n.add_argument("--modus", default="auto", choices=["auto", "deels", "live"])
    n.add_argument("--normversie", default="0.2")
    v = sub.add_parser("vervallen")
    v.add_argument("id")
    v.add_argument("--reden", required=True)
    w = sub.add_parser("wijzig")
    w.add_argument("id")
    for veld in ("scan", "normen", "ernst", "hint"):
        w.add_argument(f"--{veld}")
    a = ap.parse_args(argv)
    checks = laad()

    if a.cmd == "lijst":
        for c in checks:
            print(f"{c['id']}  v{c.get('versie', 1)}  {c.get('status', 'actief'):9}  {c['ernst']:7}  {c['scan'][:80]}")
        print(f"\n{len(actief(checks))} actief van {len(checks)}")
    elif a.cmd == "controleer":
        f = controleer(checks)
        print("In orde." if not f else "\n".join(f))
        return 1 if f else 0
    elif a.cmd == "nieuw":
        letter = a.domein.strip().upper()[0]
        dom = next((c["domein"] for c in checks if c["domein"].startswith(letter + ".")), a.domein)
        cid = volgend_id(checks, letter)
        if a.ernst not in ERNST:
            ap.error(f"ernst moet een van {ERNST} zijn")
        checks.append({"id": cid, "domein": dom, "scan": a.scan, "normen": a.normen, "ernst": a.ernst, "modus": a.modus,
                       "module": a.module, "methode": a.methode, "hint": a.hint, "sinds": a.normversie, "versie": 1,
                       "status": "actief"})
        checks.sort(key=lambda c: (c["id"][0], int(c["id"][2:])))
        bewaar(checks)
        print(f"Toegevoegd: {cid}. Vergeet niet de controle zelf te schrijven met @check(\"{cid}\").")
    elif a.cmd == "vervallen":
        c = next((c for c in checks if c["id"] == a.id), None)
        if not c:
            ap.error(f"onbekend ID: {a.id}")
        c["status"], c["vervallen_reden"], c["versie"] = "vervallen", a.reden, c.get("versie", 1) + 1
        bewaar(checks)
        print(f"{a.id} vervallen. Het ID wordt nooit opnieuw gebruikt.")
    elif a.cmd == "wijzig":
        c = next((c for c in checks if c["id"] == a.id), None)
        if not c:
            ap.error(f"onbekend ID: {a.id}")
        changed = False
        for veld in ("scan", "normen", "ernst", "hint"):
            val = getattr(a, veld)
            if val is not None and val != c.get(veld):
                c[veld], changed = val, True
        if changed and (a.scan or a.normen or a.ernst):
            c["versie"] = c.get("versie", 1) + 1
        bewaar(checks)
        print(f"{a.id} bijgewerkt, nu versie {c.get('versie')}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
