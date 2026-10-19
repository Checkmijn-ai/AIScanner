"""checkmijn.ai in een pipeline (GitHub Actions).

1. Haalt het manifest van de dagversie op en controleert de Ed25519-handtekening met de vaste publieke sleutel.
2. Haalt de scanner van vandaag op en controleert het controlegetal (SHA-256) uit het manifest.
3. Scant de repository zonder netwerk. De code verlaat de runner niet.
4. Schrijft de uitslag in de samenvatting van de run; het volledige rapport wordt een artefact van de run.
5. Alleen als 'insturen' aan staat: vraagt een sessiecode en levert bewijs.json in (geen code, geen paden).

Instellingen via omgevingsvariabelen (zie action.yml).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

HIER = Path(__file__).resolve().parent
MANIFEST_URL = os.environ.get("CM_MANIFEST", "https://klankenreis.github.io/checkmijn-scanner/latest.json")
PAD = Path(os.environ.get("CM_PAD") or os.environ.get("GITHUB_WORKSPACE", ".")).resolve()
OUT = Path(os.environ.get("CM_OUT", "checkmijn-rapport")).resolve()
INSTUREN = os.environ.get("CM_INSTUREN", "false").lower() == "true"
FAAL_BIJ = os.environ.get("CM_FAAL_BIJ", "nooit").lower()  # nooit | kritiek | hoog
TMP = Path(os.environ.get("RUNNER_TEMP", "/tmp"))
SAMENVATTING = os.environ.get("GITHUB_STEP_SUMMARY")


def log(*a):
    print(*a, flush=True)


def haal(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read()


def schrijf_samenvatting(tekst: str):
    if SAMENVATTING:
        with open(SAMENVATTING, "a", encoding="utf-8") as f:
            f.write(tekst + "\n")
    log(tekst)


def controleer_handtekening(m: dict) -> str:
    sleutel = HIER / "public-key.pem"
    h = m.get("handtekening")
    if not sleutel.exists() or "BEGIN PUBLIC KEY" not in sleutel.read_text():
        return "niet gecontroleerd (nog geen publieke sleutel in de action)"
    if not h:
        sys.exit("checkmijn.ai: het manifest is niet ondertekend. Gestopt.")
    from cryptography.hazmat.primitives import serialization
    pub = serialization.load_pem_public_key(sleutel.read_bytes())
    data = json.dumps({k: v for k, v in m.items() if k != "handtekening"}, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode()
    try:
        pub.verify(base64.b64decode(h["waarde"]), data)
    except Exception:
        sys.exit("checkmijn.ai: de handtekening van het manifest klopt niet. Gestopt.")
    return "geldig (Ed25519)"


def main() -> int:
    log(f"checkmijn.ai · manifest: {MANIFEST_URL}")
    m = json.loads(haal(MANIFEST_URL))
    handtekening = controleer_handtekening(m)
    pyz = TMP / "checkmijn.pyz"
    pyz.write_bytes(haal(m["url"]))
    sha = hashlib.sha256(pyz.read_bytes()).hexdigest()
    if sha != m["sha256"]:
        sys.exit(f"checkmijn.ai: controlegetal klopt niet ({sha} ≠ {m['sha256']}). Gestopt.")
    log(f"Dagversie {m['dagversie']} · controlegetal klopt · handtekening {handtekening}")

    nonce = None
    if INSTUREN:
        r = subprocess.run([sys.executable, str(pyz), "sessie", m["api"]], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            nonce = r.stdout.strip()
        else:
            log(f"::warning::Geen sessiecode van de API ({r.stderr.strip() or 'geen antwoord'}); er wordt niets ingeleverd.")

    cmd = [sys.executable, str(pyz), str(PAD), "--offline", "--out", str(OUT), "--bewijs"]
    if nonce:
        cmd += ["--nonce", nonce]
    scan = subprocess.run(cmd, text=True)
    if scan.returncode not in (0, 2):
        sys.exit(f"checkmijn.ai: de scanner stopte met een fout (code {scan.returncode}).")

    rap = json.loads((OUT / "rapport.json").read_text())
    s = rap["samenvatting"]
    sc = s.get("score") or {}
    letter = sc.get("letter") or "geen"
    regels = [
        "## checkmijn.ai — scanscore",
        "",
        f"**Score: {letter}** · niveau {s.get('niveau', 1)} · dagversie {m['dagversie']} · commit `{(s.get('commit') or '')[:12]}`",
        "",
        f"{sc.get('uitleg', '')}",
        "",
        f"Gescand: {s['gescand']} van {s['totaal']} checks · kritiek {s['ernst']['Kritiek']} · hoog {s['ernst']['Hoog']} · "
        f"middel {s['ernst']['Middel']} · laag {s['ernst']['Laag']}",
        "",
        "| Check | Scan | Status | Bevindingen |",
        "| --- | --- | --- | --- |",
    ]
    for c in rap["checks"]:
        if c["status"] in ("Bevinding", "Niet gescand"):
            zw = c["bevindingen"][0]["ernst"] if c["bevindingen"] else ""
            regels.append(f"| {c['id']} | {c['scan'][:90]} | {c['status']} | {len(c['bevindingen'])} {zw} |")
    regels += ["", "Het volledige rapport (met bestand en regel per bevinding) staat bij de artefacten van deze run. "
               "Het blijft in GitHub en gaat niet naar checkmijn.ai.", ""]

    if nonce:
        r = subprocess.run([sys.executable, str(pyz), "inleveren", str(OUT / "bewijs.json"), m["api"]],
                           capture_output=True, text=True)
        if r.returncode == 0:
            d = json.loads(r.stdout)
            regels += [f"**Scorepagina:** {d.get('pagina')}", "",
                       f"[![checkmijn.ai]({d.get('badge')})]({d.get('pagina')})", ""]
        else:
            regels += [f"Inleveren geweigerd: {r.stderr.strip()}", ""]

    regels.append("*De scanscore is een uitslag van de scan op een bepaald moment. Ze is geen keurmerk, certificaat "
                  "of garantie dat software veilig is.*")
    schrijf_samenvatting("\n".join(regels))

    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"score={letter}\nrapport={OUT}\n")

    k, h = s["ernst"]["Kritiek"], s["ernst"]["Hoog"]
    if (FAAL_BIJ == "kritiek" and k) or (FAAL_BIJ == "hoog" and (k or h)):
        log(f"::error::checkmijn.ai: {k} kritieke en {h} hoge bevinding(en).")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
