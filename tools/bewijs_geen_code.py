"""Publiek bewijs dat er geen code naar buiten gaat. Draait elke nacht in GitHub Actions (workflow Dagversie).

Wat het nagaat, op een demo-app vol nepgeheimen:
  1. De scan zonder netwerk: met --offline maakt de scanner geen enkele netwerkverbinding (strace telt connect-aanroepen),
     en in een afgesloten netwerk (unshare --net) werkt de scan gewoon.
  2. Het bewijsbestand: alleen de toegelaten velden, geen bestandsnamen, geen code, geen geheimen.
  3. Het rapport voor de rapportlink: wat naar checkmijn.ai gaat, is versleuteld; de sleutel zit alleen in de link (na #)
     en gaat niet mee.

Gebruik: python tools/bewijs_geen_code.py UITVOER.json [--strace] [--unshare]
Stopt met code 1 als één controle faalt.
"""
from __future__ import annotations

import base64
import datetime as dt
import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOEGELATEN = {"formaat", "tijd", "nonce", "scanner", "project", "niveau", "soort", "resultaten", "score", "ernst"}
PER_CHECK = {"id", "status", "zwaarste", "aantal", "onterecht"}


def geheimen(demo: Path) -> list[str]:
    """De nepgeheimen die maak_demo.py in de app zette (lang genoeg om niet toevallig voor te komen)."""
    tekst = "\n".join(p.read_text(errors="ignore") for p in demo.rglob("*") if p.is_file() and ".git" not in p.parts)
    pat = r"(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|ghp_[A-Za-z0-9]{36}|sk_live_[A-Za-z0-9]{32}|AKIA[A-Z2-7]{16})"
    return sorted(set(re.findall(pat, tekst)))


def scan(demo: Path, uit: Path, voor: list[str]) -> subprocess.CompletedProcess:
    cmd = voor + [sys.executable, "-m", "aiscan", str(demo), "--offline", "--bewijs", "--nonce", "bewijs-test", "--out", str(uit)]
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(ROOT)})


def main() -> int:
    doel = Path(sys.argv[1])
    met_strace = "--strace" in sys.argv and shutil.which("strace")
    met_unshare = "--unshare" in sys.argv
    tmp = Path(tempfile.mkdtemp())
    demo = tmp / "demo"
    subprocess.run([sys.executable, str(ROOT / "tests" / "maak_demo.py"), str(demo)], check=True, capture_output=True)
    nep = geheimen(demo)
    controles = []

    def noteer(naam, ok, uitleg):
        controles.append({"controle": naam, "ok": bool(ok), "uitleg": uitleg})

    # 1a. netwerkverbindingen tellen
    if met_strace:
        trace = tmp / "trace.txt"
        r = scan(demo, tmp / "uit1", ["strace", "-f", "-qq", "-e", "trace=connect", "-o", str(trace)])
        regels = trace.read_text(errors="ignore").splitlines() if trace.exists() else []
        inet = [x for x in regels if "AF_INET" in x]
        noteer("Geen netwerkverbinding tijdens de scan", r.returncode in (0, 2) and not inet,
               f"{len(inet)} verbinding(en) naar het internet geprobeerd (strace telt elke connect-aanroep van de scanner)."
               + (f" Eerste: {inet[0][:160]}" if inet else ""))
    # 1b. in een afgesloten netwerk
    if met_unshare:
        r = scan(demo, tmp / "uit2", ["sudo", "-E", "unshare", "--net", "--"])
        noteer("Scan werkt zonder netwerk", r.returncode in (0, 2) and (tmp / "uit2" / "bewijs.json").exists(),
               "De scan liep in een netwerk zonder enige verbinding naar buiten (unshare --net) en gaf een volledig rapport.")
    # 2. het bewijsbestand
    r = scan(demo, tmp / "uit3", [])
    b = json.loads((tmp / "uit3" / "bewijs.json").read_text())
    ruw = (tmp / "uit3" / "bewijs.json").read_text()
    paden = [str(p.relative_to(demo)) for p in demo.rglob("*") if p.is_file() and ".git" not in p.parts]
    lek_paden = [p for p in paden if len(p) > 6 and p in ruw]
    noteer("Bewijsbestand bevat alleen uitkomsten",
           set(b) <= TOEGELATEN and all(set(x) <= PER_CHECK for x in b["resultaten"]) and not lek_paden,
           f"Velden: {', '.join(sorted(b))}. Per check alleen {', '.join(sorted(PER_CHECK))}. "
           f"Bestandsnamen uit het project gevonden: {len(lek_paden)}.")
    noteer("Bewijsbestand bevat geen geheimen", nep and not any(g in ruw for g in nep),
           f"{len(nep)} nepsleutels in de demo-app (zoals van OpenAI, GitHub en Stripe); geen ervan in het bewijsbestand."
           if not any(g in ruw for g in nep) else "Een geheim staat in het bewijsbestand!")
    # 3. de rapportlink: wat er naar checkmijn.ai gaat
    sys.path.insert(0, str(ROOT / "action"))
    os.environ.update({"CM_OUT": str(tmp / "uit3"), "ACTIONS_ID_TOKEN_REQUEST_URL": "x", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "x",
                       "GITHUB_EVENT_NAME": "push"})
    import scan_ci  # noqa: E402
    scan_ci.OUT = tmp / "uit3"
    verstuurd = {}

    class Antw:
        def __init__(self, data): self.data = data
        def read(self): return self.data
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def nep_urlopen(req, timeout=None):
        verstuurd["body"] = req.data
        verstuurd["url"] = req.full_url
        return Antw(json.dumps({"id": "test", "verloopt": "2099-01-01"}).encode())

    import urllib.request
    echt = urllib.request.urlopen
    urllib.request.urlopen = nep_urlopen
    scan_ci.oidc_token = lambda: "token"
    try:
        link, _ = scan_ci.maak_rapport_link({"api": "https://checkmijn.ai", "instructie": "https://checkmijn.ai/scan.md"})
    finally:
        urllib.request.urlopen = echt
    body = verstuurd.get("body", b"")
    html = (tmp / "uit3" / "rapport.html").read_bytes()
    sleutel_b64 = link.split("#k=", 1)[1]
    d = json.loads(body)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ontb = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))  # noqa: E731
    terug = gzip.decompress(AESGCM(ontb(sleutel_b64)).decrypt(ontb(d["iv"]), ontb(d["data"]), None))
    noteer("Rapport gaat alleen versleuteld naar checkmijn.ai",
           sleutel_b64.encode() not in body and not any(g.encode() in body for g in nep) and b"<html" not in body
           and set(d) == {"versie", "alg", "iv", "data"} and terug == html,
           "Verstuurd: alleen versie, algoritme (AES-256-GCM), iv en versleutelde data. De sleutel zit alleen in de link "
           "na #, en die stuurt een browser nooit naar de server.")
    alles = all(c["ok"] for c in controles)
    uit = {"datum": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "ok": alles, "controles": controles,
           "run": (f"{os.environ.get('GITHUB_SERVER_URL')}/{os.environ.get('GITHUB_REPOSITORY')}/actions/runs/"
                   f"{os.environ.get('GITHUB_RUN_ID')}") if os.environ.get("GITHUB_RUN_ID") else None}
    doel.write_text(json.dumps(uit, indent=1, ensure_ascii=False))
    for c in controles:
        print(("OK   " if c["ok"] else "FOUT ") + c["controle"] + " — " + c["uitleg"])
    if os.environ.get("GITHUB_ACTIONS"):
        print(f"::notice title=Bewijs geen code::{'alles in orde' if alles else 'FOUT'}: "
              + " | ".join(("OK " if c["ok"] else "FOUT ") + c["controle"] for c in controles))
    samen = os.environ.get("GITHUB_STEP_SUMMARY")
    if samen:
        with open(samen, "a") as f:
            f.write("## Bewijs: er gaat geen code naar buiten\n\n| Controle | Uitkomst | Uitleg |\n| --- | --- | --- |\n")
            for c in controles:
                f.write(f"| {c['controle']} | {'✅' if c['ok'] else '❌'} | {c['uitleg']} |\n")
    return 0 if alles else 1


if __name__ == "__main__":
    sys.exit(main())
