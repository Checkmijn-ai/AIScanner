"""Testbank: scant bewust kwetsbare apps en schone apps (tests/testbank.yaml) en schrijft testbank.json.

Per kwetsbare app: welke gedocumenteerde lekken de scanner vond en welke hij miste.
Per schone app: welke kritieke of hoge meldingen er zijn die we niet als terecht beoordeeld hebben (vals alarm).

Gebruik: python tools/testbank.py UITVOER.json [--map WERKMAP]
"""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ZWAAR = {"Kritiek", "Hoog", "Middel"}


def haal(repo: str, commit: str, doel: Path) -> None:
    if (doel / ".git").exists():
        return
    doel.mkdir(parents=True, exist_ok=True)
    git = lambda *a: subprocess.run(["git", "-C", str(doel), *a], check=True, capture_output=True)  # noqa: E731
    git("init", "-q")
    git("remote", "add", "origin", f"https://github.com/{repo}")
    git("fetch", "-q", "--depth", "1", "origin", commit)
    git("checkout", "-q", "FETCH_HEAD")


def scan(pad: Path, uit: Path) -> dict:
    subprocess.run([sys.executable, "-m", "aiscan", str(pad), "--offline", "--out", str(uit)], cwd=ROOT,
                   capture_output=True, env={**os.environ, "PYTHONPATH": str(ROOT)})
    return json.loads((uit / "rapport.json").read_text())


def past(b: dict, regel: dict) -> bool:
    import re
    best = (b.get("bestand") or "").lstrip("./")
    if regel.get("zoek") and not re.search(regel["zoek"], b.get("titel", ""), re.I):
        return False
    return not regel.get("bestand") or best == regel["bestand"] or best.endswith("/" + regel["bestand"])


def main() -> int:
    doel = Path(sys.argv[1])
    werk = Path(sys.argv[sys.argv.index("--map") + 1]) if "--map" in sys.argv else Path(tempfile.mkdtemp())
    bank = yaml.safe_load((ROOT / "tests" / "testbank.yaml").read_text(encoding="utf-8"))
    apps = []
    for app in bank["apps"]:
        naam = app["naam"]
        pad = werk / (app.get("repo", naam).replace("/", "_").replace(" ", "_"))
        try:
            if app.get("demo"):
                if not pad.exists():
                    subprocess.run([sys.executable, str(ROOT / "tests" / "maak_demo.py"), str(pad), "--hersteld"],
                                   check=True, capture_output=True)
            else:
                haal(app["repo"], app["commit"], pad)
            rap = scan(pad, werk / ("uit-" + pad.name))
        except Exception as e:  # noqa: BLE001
            apps.append({"naam": naam, "soort": app["soort"], "fout": f"{type(e).__name__}: {e}"[:300]})
            continue
        s = rap["samenvatting"]
        per = {c["id"]: c for c in rap["checks"]}
        bron = (lambda b: f"https://github.com/{app['repo']}/blob/{app['commit']}/{b}") if app.get("repo") else (lambda b: None)
        r = {"naam": naam, "soort": app["soort"], "over": app.get("over", ""), "repo": app.get("repo"),
             "commit": app.get("commit"), "letter": s["score"].get("letter"), "dekking": s["score"].get("dekking"),
             "ernst": s["ernst"]}
        if app["soort"] == "kwetsbaar":
            r["lekken"] = []
            for lek in app["lekken"]:
                treffers = [b for cid in lek["checks"] for b in per.get(cid, {}).get("bevindingen", [])
                            if b["ernst"] in ZWAAR and past(b, lek)]
                r["lekken"].append({"wat": lek["wat"], "checks": lek["checks"], "bestand": lek.get("bestand"),
                                    "bron": bron(lek["bestand"]) if lek.get("bestand") else None,
                                    "gevonden": bool(treffers),
                                    "als": (f"{treffers[0]['ernst']}: {treffers[0]['titel']}"[:140] if treffers else None)})
        else:
            terecht = app.get("terecht", [])
            vals, goed = [], 0
            for c in rap["checks"]:
                for b in c["bevindingen"]:
                    if b["ernst"] not in ("Kritiek", "Hoog"):
                        continue
                    if any(c["id"] in t["checks"] and past(b, t) for t in terecht):
                        goed += 1
                    else:
                        vals.append({"check": c["id"], "ernst": b["ernst"], "titel": b["titel"][:140],
                                     "bestand": b.get("bestand"), "nakijken": bool(b.get("bevestigen"))})
            r.update({"terecht": [t["wat"] for t in terecht], "terecht_aantal": goed, "vals_alarm": vals})
        apps.append(r)
    kw = [a for a in apps if a.get("soort") == "kwetsbaar" and "lekken" in a]
    sc = [a for a in apps if a.get("soort") == "schoon" and "vals_alarm" in a]
    totaal = {"lekken": sum(len(a["lekken"]) for a in kw), "gevonden": sum(sum(x["gevonden"] for x in a["lekken"]) for a in kw),
              "vals_alarm": sum(len(a["vals_alarm"]) for a in sc), "schone_apps": len(sc),
              "fouten": sum(1 for a in apps if "fout" in a)}
    uit = {"datum": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "totaal": totaal, "apps": apps,
           "run": (f"{os.environ.get('GITHUB_SERVER_URL')}/{os.environ.get('GITHUB_REPOSITORY')}/actions/runs/"
                   f"{os.environ.get('GITHUB_RUN_ID')}") if os.environ.get("GITHUB_RUN_ID") else None}
    doel.write_text(json.dumps(uit, indent=1, ensure_ascii=False))
    print(f"Gevonden {totaal['gevonden']} van {totaal['lekken']} lekken; {totaal['vals_alarm']} vals alarm op "
          f"{totaal['schone_apps']} schone apps; {totaal['fouten']} fout(en).")
    for a in kw:
        for x in a["lekken"]:
            print(("  ok    " if x["gevonden"] else "  GEMIST") + f" {a['naam']}: {x['wat']}")
    for a in sc:
        for v in a["vals_alarm"]:
            print(f"  VALS? {a['naam']}: {v['check']} {v['ernst']} {v['titel']} ({v['bestand']})")
    samen = os.environ.get("GITHUB_STEP_SUMMARY")
    if samen:
        with open(samen, "a") as f:
            f.write(f"## Testbank\n\nGevonden **{totaal['gevonden']} van {totaal['lekken']}** gedocumenteerde lekken; "
                    f"**{totaal['vals_alarm']}** vals alarm op {totaal['schone_apps']} schone apps.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
