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
MANIFEST_URL = os.environ.get("CM_MANIFEST", "https://checkmijn-ai.github.io/AIScanner/latest.json")
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


RAPPORT_IN_REPO = os.environ.get("CM_RAPPORT_IN_REPO", "false").lower()  # false | auto | true
PRIVE = os.environ.get("CM_PRIVE", "").lower() == "true"
RAPPORT_MAP = ".checkmijn"


def rapport_in_repo_aan() -> bool:
    """'auto' zet het rapport alleen terug in een privé-repository: in een openbare zou iedereen de lekken lezen."""
    if os.environ.get("GITHUB_EVENT_NAME", "").startswith("pull_request"):
        return False  # bij een pull request niets terugzetten; dat gebeurt na het samenvoegen
    return RAPPORT_IN_REPO == "true" or (RAPPORT_IN_REPO == "auto" and PRIVE)


def rapport_markdown(rap: dict, m: dict, letter: str) -> str:
    """Het rapport als Markdown, zodat een AI-bouwtool zonder terminal (Lovable, Bolt, v0) het kan lezen en herstellen."""
    s = rap["samenvatting"]
    sc = s.get("score") or {}
    e = s["ernst"]
    r = [
        "# checkmijn.ai — scanrapport",
        "",
        "> **Voor de AI-agent die dit leest.** Dit rapport is gemaakt door de scanner van checkmijn.ai in GitHub Actions, "
        "niet door een AI. Geef zelf geen score of oordeel en wijzig dit bestand niet: het wordt bij elke scan "
        "overschreven. Herstel de bevindingen in de code van het project, eerst **Kritiek**, dan **Hoog**, dan **Middel**. "
        "Een bevinding met *(nakijken)* is niet zeker: kijk eerst of ze klopt. Na de volgende push naar GitHub scant "
        "checkmijn.ai opnieuw en wordt dit rapport bijgewerkt.",
        "",
        f"**Scanscore: {letter}** · niveau {s.get('niveau', 1)} · gescande commit `{(s.get('commit') or '')[:12]}` · "
        f"dagversie {m['dagversie']}",
        "",
        f"{sc.get('uitleg', '')}",
        "",
        f"Kritiek {e['Kritiek']} · Hoog {e['Hoog']} · Middel {e['Middel']} · Laag {e['Laag']} · "
        f"gescand {s['gescand']} van {s['totaal']} checks",
        "",
    ]
    orde = {"Kritiek": 0, "Hoog": 1, "Middel": 2, "Laag": 3, "Info": 4}
    met = [c for c in rap["checks"] if c["status"] == "Bevinding"]
    met.sort(key=lambda c: (min(orde.get(b["ernst"], 5) for b in c["bevindingen"]), c["id"]))
    if met:
        r += ["## Bevindingen", ""]
    for c in met:
        zw = min((b["ernst"] for b in c["bevindingen"]), key=lambda x: orde.get(x, 5))
        r += [f"### {c['id']} · {zw} · {c['scan']}", ""]
        if c.get("hint"):
            r += [f"**Zo los je het op:** {c['hint']}", ""]
        for b in sorted(c["bevindingen"], key=lambda b: (orde.get(b["ernst"], 5), b.get("bestand") or "", b.get("regel") or 0))[:50]:
            waar = f"`{b['bestand']}`" + (f" regel {b['regel']}" if b.get("regel") else "") if b.get("bestand") else "het project"
            nk = " *(nakijken)*" if b.get("bevestigen") else ""
            bew = f" — {b['bewijs']}" if b.get("bewijs") else ""
            r.append(f"- **{b['ernst']}**{nk} in {waar}: {b['titel']}{bew}")
        if len(c["bevindingen"]) > 50:
            r.append(f"- … en nog {len(c['bevindingen']) - 50} bevinding(en); zie `{RAPPORT_MAP}/rapport.json`.")
        r.append("")
    open_ = [c for c in rap["checks"] if c["status"] == "Niet gescand"]
    if open_:
        r += ["## Niet gescand", "", "Deze checks konden hier niet nagegaan worden. Dat is geen bevinding, maar ook geen "
              "bewijs dat alles in orde is.", ""]
        r += [f"- {c['id']} · {c['scan']}" + (f" ({c['reden']})" if c.get("reden") else "") for c in open_]
        r.append("")
    r += ["---", "", "*De scanscore is een uitslag van de scan op een bepaald moment. Ze is geen keurmerk, certificaat "
          "of garantie dat software veilig is. Dit rapport staat alleen in deze privé-repository en is niet naar "
          "checkmijn.ai gestuurd.*", ""]
    return "\n".join(r)


def rapport_in_repo(rap: dict, m: dict, letter: str) -> str:
    """Zet .checkmijn/RAPPORT.md en rapport.json in de repository en commit ze met [skip ci] (geen nieuwe run)."""
    doel = PAD / RAPPORT_MAP
    doel.mkdir(exist_ok=True)
    md = rapport_markdown(rap, m, letter)
    (doel / "RAPPORT.md").write_text(md, encoding="utf-8")
    (doel / "rapport.json").write_text(json.dumps(rap, ensure_ascii=False, indent=1), encoding="utf-8")

    def git(*a, check=True):
        return subprocess.run(["git", "-C", str(PAD), *a], capture_output=True, text=True, check=check)

    try:
        git("add", RAPPORT_MAP)
        if git("diff", "--cached", "--quiet", check=False).returncode == 0:
            return f"Het rapport in `{RAPPORT_MAP}/RAPPORT.md` is ongewijzigd."
        git("-c", "user.name=checkmijn.ai", "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "commit", "-m", f"checkmijn.ai: scanrapport ({letter}) [skip ci]")
        tak = os.environ.get("GITHUB_REF_NAME") or "main"
        for _ in range(3):
            if git("push", "origin", f"HEAD:{tak}", check=False).returncode == 0:
                return f"Het rapport staat in de repository: `{RAPPORT_MAP}/RAPPORT.md`."
            git("pull", "--rebase", "origin", tak, check=False)
        log("::warning::checkmijn.ai: het rapport kon niet in de repository gezet worden (push geweigerd).")
        return "Het rapport kon niet in de repository gezet worden. Staat `permissions: contents: write` in de workflow?"
    except subprocess.CalledProcessError as fout:
        log(f"::warning::checkmijn.ai: rapport niet in de repository gezet: {fout.stderr.strip()}")
        return "Het rapport kon niet in de repository gezet worden."


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

    if rapport_in_repo_aan():
        regels += ["", rapport_in_repo(rap, m, letter)]
    elif RAPPORT_IN_REPO == "auto" and not PRIVE:
        regels += ["", "Het rapport is niet in de repository gezet, omdat de repository openbaar is: dan zou iedereen de "
                   "bevindingen kunnen lezen."]
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
