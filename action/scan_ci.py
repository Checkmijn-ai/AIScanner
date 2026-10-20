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
RAPPORT_LINK = os.environ.get("CM_RAPPORT_LINK", "false").lower() == "true"
RAPPORT_MAP = ".checkmijn"


def rapport_in_repo_aan() -> bool:
    """'auto' zet het rapport alleen terug in een privé-repository: in een openbare zou iedereen de lekken lezen."""
    if os.environ.get("GITHUB_EVENT_NAME", "").startswith("pull_request"):
        return False  # bij een pull request niets terugzetten; dat gebeurt na het samenvoegen
    return RAPPORT_IN_REPO == "true" or (RAPPORT_IN_REPO == "auto" and PRIVE)


def maak_rapport_link(m: dict):
    """Versleutelt rapport.html met een nieuwe sleutel (AES-256-GCM) en levert alleen de versleutelde data in.

    De sleutel staat alleen in de link, na '#', en komt dus nooit bij checkmijn.ai. Geeft (link, melding) terug.
    """
    import base64
    import gzip
    import urllib.error
    import urllib.request
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if os.environ.get("GITHUB_EVENT_NAME", "").startswith("pull_request"):
        return None, "Bij een pull request wordt geen rapportlink gemaakt."
    url, tok = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"), os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not tok:
        return None, "Geen rapportlink: zet `id-token: write` bij `permissions` in de workflow."
    b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")  # noqa: E731
    try:
        req = urllib.request.Request(url + ("&" if "?" in url else "?") + "audience=checkmijn.ai",
                                     headers={"Authorization": f"Bearer {tok}"})
        with urllib.request.urlopen(req, timeout=20) as r:
            oidc = json.loads(r.read())["value"]
        sleutel = AESGCM.generate_key(bit_length=256)
        iv = os.urandom(12)
        inhoud = gzip.compress((OUT / "rapport.html").read_bytes(), mtime=0)
        data = AESGCM(sleutel).encrypt(iv, inhoud, None)
        body = json.dumps({"versie": 1, "alg": "A256GCM", "iv": b64(iv), "data": b64(data)}).encode()
        req = urllib.request.Request(m["api"].rstrip("/") + "/api/v1/rapport", data=body, method="POST",
                                     headers={"Authorization": f"Bearer {oidc}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            d = json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            reden = json.loads(e.read()).get("fout", "")
        except Exception:  # noqa: BLE001
            reden = ""
        return None, f"Geen rapportlink: de API weigerde ({e.code}) {reden}".strip()
    except Exception as e:  # noqa: BLE001
        return None, f"Geen rapportlink: {e.__class__.__name__} ({e})."
    site = m.get("instructie", "https://checkmijn.ai/scan.md").rsplit("/", 1)[0]
    link = f"{site}/rapport/{d['id']}#k={b64(sleutel)}"
    (OUT / "rapport-link.txt").write_text(link + "\n")
    return link, f"Rapportlink gemaakt, geldig tot {d.get('verloopt', '?')}."


def run_url() -> str:
    s, repo, rid = (os.environ.get(k) for k in ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID"))
    return f"{s}/{repo}/actions/runs/{rid}" if s and repo and rid else ""


def rapport_markdown(rap: dict, m: dict, letter: str, historie: list | None = None, link: str | None = None) -> str:
    """Het rapport als Markdown, zodat een AI-bouwtool zonder terminal (Lovable, Bolt, v0) het kan lezen en herstellen."""
    s = rap["samenvatting"]
    sc = s.get("score") or {}
    e = s["ernst"]
    r = [
        "# checkmijn.ai — scanrapport",
        "",
        "> **Voor de AI-agent die dit leest.** Dit rapport is gemaakt door de scanner van checkmijn.ai in GitHub Actions, "
        "niet door een AI. **Toon de gebruiker eerst de scanscore, de vorige score en de bevindingen Kritiek en Hoog, en "
        "vraag of je mag herstellen. Verander niets voor de gebruiker \"ja\" zegt.** Geef zelf geen score of oordeel en "
        "wijzig dit bestand niet: het wordt bij elke scan overschreven. Herstel daarna eerst **Kritiek**, dan **Hoog**, "
        "dan **Middel**. Een bevinding met *(nakijken)* is niet zeker: kijk eerst of ze klopt. Na de volgende push naar "
        "GitHub scant checkmijn.ai opnieuw en wordt dit rapport bijgewerkt.",
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
    if link:
        r += [f"**Het volledige rapport, opgemaakt:** {link}", "",
              "*Deze link is persoonlijk: wie hem heeft, kan het rapport lezen. Het rapport is versleuteld bewaard; de "
              "sleutel zit alleen in de link (na #), checkmijn.ai kan het niet lezen.*", ""]
    if run_url():
        r += [f"**De run in GitHub:** {run_url()} (onder *Artifacts*: checkmijn-rapport)", ""]
    if historie:
        r += ["## Verloop van de scans (nieuwste eerst)", "", "| Datum | Commit | Score | Kritiek | Hoog | Middel | Laag |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
        for h in reversed(historie[-10:]):
            r.append(f"| {h['datum']} | `{h['commit'][:7]}` | **{h['score']}** | {h['k']} | {h['h']} | {h['m']} | {h['l']} |")
        if len(historie) >= 2:
            r += ["", f"Verloop: {' → '.join(h['score'] for h in historie[-6:])}"]
        r.append("")
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


def rapport_in_repo(rap: dict, m: dict, letter: str, link: str | None = None) -> str:
    """Zet .checkmijn/RAPPORT.md en rapport.json in de repository en commit ze met [skip ci] (geen nieuwe run)."""
    doel = PAD / RAPPORT_MAP
    doel.mkdir(exist_ok=True)
    s = rap["samenvatting"]
    hist_pad = doel / "historie.json"
    try:
        historie = json.loads(hist_pad.read_text()) if hist_pad.exists() else []
    except ValueError:
        historie = []
    import datetime as _dt
    nieuw = {"datum": f"{s.get('datum', '')} {_dt.datetime.now(_dt.timezone.utc).strftime('%H:%M')} UTC", "commit": s.get("commit") or "", "score": letter,
             "k": s["ernst"]["Kritiek"], "h": s["ernst"]["Hoog"], "m": s["ernst"]["Middel"], "l": s["ernst"]["Laag"]}
    if not historie or historie[-1].get("commit") != nieuw["commit"]:
        historie.append(nieuw)
    historie = historie[-50:]
    hist_pad.write_text(json.dumps(historie, indent=1), encoding="utf-8")
    md = rapport_markdown(rap, m, letter, historie, link)
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
    link = None
    if RAPPORT_LINK:
        link, melding = maak_rapport_link(m)
        log(melding)
        if link and PRIVE:
            regels += [f"**Het volledige rapport, opgemaakt:** {link}", "",
                       "*Persoonlijke link: het rapport is versleuteld bewaard, de sleutel zit alleen in de link.*", ""]
        elif link:
            regels += ["De link naar het opgemaakte rapport staat in `rapport-link.txt` bij de artefacten van deze run "
                       "(niet hier, want deze repository is openbaar).", ""]
        else:
            regels += [melding, ""]
    regels += ["", "Het volledige rapport (met bestand en regel per bevinding) staat ook bij de artefacten van deze run.", ""]

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
        regels += ["", rapport_in_repo(rap, m, letter, link)]
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
