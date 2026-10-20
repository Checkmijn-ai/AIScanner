"""aiscan — AI-code scan, concept 0.1.

Gebruik:
  python -m aiscan PAD [--niveau 1] [--klant NAAM] [--app NAAM] [--versie X] [--out MAP]
                       [--url https://app.example.com] [--github-token TOKEN] [--offline]

Scan alleen software waarvoor je schriftelijke toestemming van de eigenaar hebt.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import __version__
from .checks.supply import write_sbom
from .report import write_html, write_json
from .runner import run, summarize, to_json


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aiscan", description="AI-code scan: controles met vaste regels, gekoppeld aan normen en wetten.")
    ap.add_argument("pad", help="map met de broncode (bij voorkeur een git-repository)")
    ap.add_argument("--niveau", type=int, default=1, choices=[1], help="pakket; deze versie bevat niveau 1 (45 scans)")
    ap.add_argument("--klant", default="[klant]")
    ap.add_argument("--app", default=None)
    ap.add_argument("--versie", default="")
    ap.add_argument("--scope", default=None, help="omschrijving van de scope voor het rapport")
    ap.add_argument("--uitvoerder", default="[Bedrijfsnaam]")
    ap.add_argument("--out", default="aiscan-rapport", help="uitvoermap")
    ap.add_argument("--url", default=None, help="live site of app voor D-12, E-08, O-04 tot O-06, Y-01, Y-02 en Y-04")
    ap.add_argument("--github-token", default=None, help="token met leesrechten voor R-03 en R-13")
    ap.add_argument("--offline", action="store_true", help="geen netwerk: geen register, GitHub-API of live site")
    ap.add_argument("--alleen", default=None, help="komma-gescheiden lijst van scan-ID's")
    ap.add_argument("--soort", default="Zelfcontrole", choices=["Zelfcontrole", "Geverifieerde scan"],
                    help="Zelfcontrole (standaard) of Geverifieerde scan (alleen als een erkende uitvoerder de scan deed)")
    ap.add_argument("--bewijs", action="store_true", help="schrijf ook bewijs.json (zonder code of paden) om in te leveren bij de API")
    ap.add_argument("--nonce", default=None, help="sessiecode van de API; komt in bewijs.json")
    ap.add_argument("--version", action="version", version=f"aiscan {__version__}")
    a = ap.parse_args(argv)

    target = Path(a.pad)
    if not target.is_dir():
        ap.error(f"map niet gevonden: {target}")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    app = a.app or target.resolve().name
    t0 = time.time()
    print(f"aiscan {__version__} — {app} — niveau {a.niveau}")
    if a.url:
        print(f"Live controles op {a.url}: alleen met schriftelijke toestemming van de eigenaar.")
    proj, results = run(str(target), a.niveau, url=a.url, offline=a.offline, github_token=a.github_token,
                        only=set(a.alleen.split(",")) if a.alleen else None)
    n = write_sbom(proj, out / "sbom.json", app)
    scope = a.scope or ("broncode in " + target.resolve().name + (f" en {a.url}" if a.url else "; geen live site"))
    summary = summarize(proj, results, {"klant": a.klant, "app": app, "versie": a.versie, "niveau": a.niveau,
                                        "scope": scope, "uitvoerder": a.uitvoerder, "soort": a.soort})
    write_json(out / "rapport.json", to_json(summary, results))
    write_html(out / "rapport.html", summary, results)
    if a.bewijs or a.nonce:
        from .bewijs import maak
        write_json(out / "bewijs.json", maak(proj, results, summary, a.nonce))
        print(f"Bewijs: {out / 'bewijs.json'}")
    sc = summary["score"]
    print(f"\nScanscore: {sc['letter'] or 'geen (te weinig gescand)'} — {sc['uitleg']}")
    print(f"{summary['uitslag']}. Geen bevinding {summary['status']['Geen bevinding']} · bevinding {summary['status']['Bevinding']} · "
          f"niet gescand {summary['status']['Niet gescand']} · n.v.t. {summary['status']['Niet van toepassing']}")
    print(f"Bevindingen: {summary['ernst']}")
    print(f"Rapport: {out / 'rapport.html'} · data: {out / 'rapport.json'} · SBOM: {out / 'sbom.json'} ({n} componenten)")
    print(f"Duur: {time.time() - t0:.1f} s")
    return 0 if summary["ernst"]["Kritiek"] + summary["ernst"]["Hoog"] == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
