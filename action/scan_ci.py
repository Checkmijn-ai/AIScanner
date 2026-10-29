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


def controleer_handtekening(m: dict, sleutel: Path | None = None) -> str:
    """Controleert de Ed25519-handtekening van het manifest. Faalt dicht: zonder geldige sleutel of handtekening
    stopt de scan, want dan weten we niet of de scanner echt van checkmijn.ai komt."""
    sleutel = sleutel or HIER / "public-key.pem"
    h = m.get("handtekening")
    if not sleutel.exists() or "BEGIN PUBLIC KEY" not in sleutel.read_text():
        sys.exit("checkmijn.ai: geen publieke sleutel gevonden in de action (action/public-key.pem). "
                 "Zonder sleutel kan de herkomst van de scanner niet gecontroleerd worden. Gestopt.")
    if not h or not isinstance(h, dict) or not h.get("waarde"):
        sys.exit("checkmijn.ai: het manifest is niet ondertekend. Gestopt.")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        pub = serialization.load_pem_public_key(sleutel.read_bytes())
    except Exception:
        sys.exit("checkmijn.ai: de publieke sleutel in de action is niet leesbaar. Gestopt.")
    if not isinstance(pub, Ed25519PublicKey):
        sys.exit("checkmijn.ai: de publieke sleutel in de action is geen Ed25519-sleutel. Gestopt.")
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
MEETELLEN = os.environ.get("CM_MEETELLEN", "false").lower() == "true"
WAARSCHUWEN = os.environ.get("CM_WAARSCHUWEN", "nee").lower()  # nee | auto | issue | faal
LABEL = "checkmijn-lekken"
MARKER = "<!-- checkmijn:sleutels "


def lekken(rap: dict) -> list[dict]:
    """Kritieke en hoge lekken in componenten (F-01) en verdachte pakketten (B-06), met een sleutel per lek."""
    import re
    uit = []
    for c in rap["checks"]:
        if c["id"] not in ("F-01", "B-06"):
            continue
        for b in c["bevindingen"]:
            if b["ernst"] not in ("Kritiek", "Hoog"):
                continue
            kop = b["titel"].split(" · ")[0]
            m = re.match(r"(.+?):\s*(\d+) bekende", kop)
            sleutel = f"{m.group(1)}#{m.group(2)}" if m else kop
            naar = re.search(r"bijwerken naar minstens (\S+)", b.get("bewijs", ""))
            ids = re.findall(r"GHSA-[\w-]+", b.get("bewijs", ""))
            uit.append({"sleutel": sleutel.replace(",", " "), "check": c["id"], "ernst": b["ernst"],
                        "titel": m.group(1) if m else kop, "aantal": int(m.group(2)) if m else 1,
                        "bestand": b.get("bestand", ""), "naar": naar.group(1) if naar else "",
                        "ids": ids[:4], "indirect": "indirect" in b["titel"]})
    return uit


def _gh(methode: str, pad: str, data=None):
    import urllib.request
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    req = urllib.request.Request(f"{api}/repos/{os.environ['GITHUB_REPOSITORY']}{pad}", method=methode,
                                 data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Authorization": f"Bearer {os.environ.get('CM_TOKEN', '')}",
                                          "Accept": "application/vnd.github+json", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        t = r.read()
        return json.loads(t) if t else {}


def lekken_tabel(lijst: list[dict]) -> str:
    regels = ["| Component | Lekken | Ernst | Bijwerken naar | Meer informatie |", "| --- | --- | --- | --- | --- |"]
    for x in lijst:
        info = ", ".join(f"[{i}](https://github.com/advisories/{i})" for i in x["ids"]) or x["check"]
        regels.append(f"| {x['titel']}{' (indirect)' if x['indirect'] else ''} | {x['aantal']} | {x['ernst']} | "
                      f"{x['naar'] or 'nog geen oplossing'} | {info} |")
    return "\n".join(regels)


def waarschuw(rap: dict) -> str:
    """Lekkenwacht: houdt één GitHub-issue bij met de kritieke en hoge lekken in je componenten.

    Nieuw lek: issue openen of een reactie toevoegen (GitHub mailt je dan). Alles opgelost: issue sluiten.
    In een openbare repository maken we geen issue (dan leest iedereen mee): daar laten we de run mislukken.
    Geeft een melding terug; zet CM_FAAL_LEK als de run moet mislukken.
    """
    if os.environ.get("GITHUB_EVENT_NAME", "").startswith("pull_request") or WAARSCHUWEN in ("nee", "false", ""):
        return ""
    lijst = lekken(rap)
    modus = WAARSCHUWEN if WAARSCHUWEN in ("issue", "faal") else ("issue" if PRIVE else "faal")
    if modus == "faal":
        if lijst:
            os.environ["CM_FAAL_LEK"] = "1"
            return f"Lekkenwacht: {len(lijst)} kritieke of hoge lekken in componenten; de run mislukt zodat GitHub je waarschuwt."
        return "Lekkenwacht: geen kritieke of hoge lekken in componenten."
    try:
        open_ = [i for i in _gh("GET", f"/issues?state=open&labels={LABEL}&per_page=5") if "pull_request" not in i]
    except Exception as e:  # noqa: BLE001
        return f"Lekkenwacht: kon de issues niet lezen ({e.__class__.__name__}). Staat `issues: write` bij permissions?"
    issue = open_[0] if open_ else None
    oud = set()
    if issue and MARKER in (issue.get("body") or ""):
        oud = set(issue["body"].split(MARKER, 1)[1].split(" -->", 1)[0].split(","))
    nu_ = {x["sleutel"] for x in lijst}
    nieuw = [x for x in lijst if x["sleutel"] not in oud]
    run = run_url()
    uitleg = ("**Wat moet je doen?** Werk de componenten bij naar de vermelde versie. Bouw je met Lovable, Bolt of v0? "
              "Vraag dan: *\"Werk de pakketten uit het nieuwste checkmijn.ai-issue bij naar de vermelde versie.\"* "
              "Na de volgende scan sluit dit issue vanzelf als alles opgelost is.")
    try:
        if lijst and not issue:
            body = (f"checkmijn.ai vond **{len(lijst)} kritieke of hoge lekken** in de componenten van dit project. "
                    f"Deze lekken zijn publiek bekend, dus aanvallers kennen ze ook.\n\n{lekken_tabel(lijst)}\n\n{uitleg}\n\n"
                    f"[De scan in GitHub]({run}) · [Lekkenwacht van checkmijn.ai](https://checkmijn.ai/hoe-het-werkt#lekkenwacht)"
                    f"\n\n{MARKER}{','.join(sorted(nu_))} -->")
            try:
                _gh("POST", "/labels", {"name": LABEL, "color": "b1161a", "description": "Lekken gevonden door checkmijn.ai"})
            except Exception:  # noqa: BLE001  label bestaat al
                pass
            i = _gh("POST", "/issues", {"title": f"checkmijn.ai: {len(lijst)} lek(ken) in componenten van dit project",
                                        "body": body, "labels": [LABEL]})
            return f"Lekkenwacht: issue #{i.get('number')} geopend ({len(lijst)} lekken). GitHub stuurt je een melding."
        if issue and nieuw:
            _gh("POST", f"/issues/{issue['number']}/comments",
                {"body": f"**{len(nieuw)} nieuw(e) lek(ken) gevonden:**\n\n{lekken_tabel(nieuw)}\n\n{uitleg}\n\n[De scan]({run})"})
            body = issue["body"].split(MARKER, 1)[0] + f"{MARKER}{','.join(sorted(nu_ | oud))} -->"
            _gh("PATCH", f"/issues/{issue['number']}", {"body": body})
            return f"Lekkenwacht: {len(nieuw)} nieuwe lekken gemeld in issue #{issue['number']}."
        if issue and not lijst:
            _gh("POST", f"/issues/{issue['number']}/comments",
                {"body": f"Alle kritieke en hoge lekken in componenten zijn opgelost. [De scan]({run}) · issue gesloten door checkmijn.ai."})
            _gh("PATCH", f"/issues/{issue['number']}", {"state": "closed", "state_reason": "completed"})
            return f"Lekkenwacht: alles opgelost, issue #{issue['number']} gesloten."
    except Exception as e:  # noqa: BLE001  de lekkenwacht mag de scan nooit laten mislukken
        return f"Lekkenwacht: kon het issue niet bijwerken ({e.__class__.__name__}). Staat `issues: write` bij permissions?"
    return f"Lekkenwacht: {len(lijst)} bekende lekken, niets nieuws." if lijst else "Lekkenwacht: geen kritieke of hoge lekken in componenten."


def oidc_token() -> str | None:
    """Een OIDC-token van GitHub voor checkmijn.ai: bewijst uit welke repository de run komt."""
    import urllib.request
    url, tok = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"), os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not tok:
        return None
    req = urllib.request.Request(url + ("&" if "?" in url else "?") + "audience=checkmijn.ai",
                                 headers={"Authorization": f"Bearer {tok}"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())["value"]


def meetellen(m: dict, letter: str) -> str:
    """Stuurt alleen de scoreletter naar checkmijn.ai voor de openbare statistiek. Geeft een melding terug."""
    import urllib.error
    import urllib.request
    if os.environ.get("GITHUB_EVENT_NAME", "").startswith("pull_request"):
        return "Bij een pull request tellen we niet mee."
    if letter not in "ABCDEFG" or len(letter) != 1:
        return "Geen score, dus niets meegeteld."
    try:
        tok = oidc_token()
        if not tok:
            return "Niet meegeteld: zet `id-token: write` bij `permissions` in de workflow."
        req = urllib.request.Request(m["api"].rstrip("/") + "/api/v1/telling", method="POST",
                                     data=json.dumps({"letter": letter, "schaal": "zelfscan"}).encode(),
                                     headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.loads(r.read())
        return d.get("melding", "Meegeteld.")
    except urllib.error.HTTPError as e:
        return f"Niet meegeteld (de API gaf {e.code})."
    except Exception as e:  # noqa: BLE001  meetellen mag de scan nooit laten mislukken
        return f"Niet meegeteld ({e.__class__.__name__})."
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
    if not (os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL") and os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")):
        return None, "Geen rapportlink: zet `id-token: write` bij `permissions` in de workflow."
    b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")  # noqa: E731
    try:
        oidc = oidc_token()
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
        "niet door een AI. **Toon de gebruiker eerst de scanscore, de vorige score, het aantal Kritiek, Hoog en Middel en de "
        "link naar het opgemaakte rapport (hieronder: plak de volledige link letterlijk, met het deel na #; die is voor de "
        "gebruiker bedoeld). Vraag één keer: \"Wil je dat ik de bevindingen herstel: Kritiek, Hoog en Middel? Je antwoord geldt "
        "voor deze hele sessie.\" Verander niets voor de gebruiker \"ja\" zegt.** Daarna vraag je het nooit opnieuw: herstel "
        "alles in één ronde, en na elke nieuwe scan meteen wat er nog echt openstaat. Lees dit bestand na elke scan opnieuw, "
        "niet uit je geheugen. Klopt een bevinding *(nakijken)* niet, verander dan niets om de scanner stil te krijgen: noem ze "
        "één keer \"onterecht gemeld\" met de reden; mag het van de gebruiker, leg ze dan vast in .checkmijn/onterecht.yml "
        "(zie checkmijn.ai/scan.md). Stop als er alleen nog Laag openstaat. Geef zelf geen score of oordeel "
        "en wijzig dit bestand niet: het wordt bij elke scan overschreven.",
        "",
        f"**Scanscore: {letter} · ZELFSCAN · {dekking(sc)}** · niveau {s.get('niveau', 1)} · gescande commit `{(s.get('commit') or '')[:12]}` · "
        f"dagversie {m['dagversie']}",
        "",
        "Een zelfscan haalt hoogstens een C: zonder kritieke of hoge bevindingen sta je op C. A en B zijn er alleen na een "
        "keuring door een erkende keurder.",
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
    ont = [(c, b) for c in rap["checks"] for b in c.get("onterecht", [])]
    if ont:
        r += ["## Onterecht gemeld (telt niet mee)", "",
              f"Deze meldingen *(nakijken)* staan in `{RAPPORT_MAP}/onterecht.yml` als onterecht, met een reden van de bouwer. "
              "Ze tellen niet mee voor de score. Alleen een melding *(nakijken)* kan daar staan, nooit een zekere bevinding.", ""]
        for c, b in ont:
            waar = f"`{b['bestand']}`" + (f" regel {b['regel']}" if b.get("regel") else "")
            r.append(f"- {c['id']} in {waar}: {b['titel']} — reden: {b['reden']}")
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


def ongewijzigd_bij_dagscan(rap: dict) -> bool:
    """Dagelijkse scan (schedule) zonder verschil met de vorige: dan niets terugzetten in de repository
    (geen dagelijkse commit), en geen nieuwe rapportlink."""
    if os.environ.get("GITHUB_EVENT_NAME") != "schedule":
        return False
    try:
        vorige = json.loads((PAD / RAPPORT_MAP / "historie.json").read_text())[-1]
    except Exception:  # noqa: BLE001
        return False
    s = rap["samenvatting"]
    return (vorige.get("commit") == (s.get("commit") or "") and
            [vorige.get(k) for k in "khml"] == [s["ernst"][e] for e in ("Kritiek", "Hoog", "Middel", "Laag")])


# Scanners van vóór 22 oktober 2026 gaven een zelfscan hoogstens een B. De grenzen schoven één letter op.
OUD_NAAR_NIEUW = {"A": "C", "B": "C", "C": "D", "D": "E", "E": "F", "F": "G", "G": "G"}


def dekking(sc: dict) -> str:
    """Hoeveel van de checks die van toepassing zijn, echt gescand is: altijd naast de letter."""
    return sc.get("dekking_tekst") or f"{round((sc.get('dekking') or 0) * 100)}% gecontroleerd"


def nieuwe_letter(sc: dict) -> str:
    """De letter op de schaal van een zelfscan (hoogstens C), ook als een oudere scanner hem nog op de oude schaal gaf."""
    letter = sc.get("letter") or "geen"
    if letter in OUD_NAAR_NIEUW and "hoogste" not in sc:
        return OUD_NAAR_NIEUW[letter]
    return letter


def werk_historie_bij(rap: dict, letter: str) -> list:
    """Leest .checkmijn/historie.json en voegt deze scan toe (alleen als het rapport in de repo komt)."""
    doel = PAD / RAPPORT_MAP
    doel.mkdir(exist_ok=True)
    s = rap["samenvatting"]
    hist_pad = doel / "historie.json"
    try:
        historie = json.loads(hist_pad.read_text()) if hist_pad.exists() else []
    except ValueError:
        historie = []
    for x in historie:  # oude scores omzetten naar de schaal van een zelfscan, zodat het verloop klopt
        if isinstance(x, dict) and x.get("schaal") != "zelfscan" and x.get("score") in OUD_NAAR_NIEUW:
            x["score"], x["schaal"] = OUD_NAAR_NIEUW[x["score"]], "zelfscan"
    import datetime as _dt
    nieuw = {"datum": f"{s.get('datum', '')} {_dt.datetime.now(_dt.timezone.utc).strftime('%H:%M')} UTC", "commit": s.get("commit") or "", "score": letter, "schaal": "zelfscan",
             "k": s["ernst"]["Kritiek"], "h": s["ernst"]["Hoog"], "m": s["ernst"]["Middel"], "l": s["ernst"]["Laag"]}
    if not historie or historie[-1].get("commit") != nieuw["commit"]:
        historie.append(nieuw)
    historie = historie[-50:]
    hist_pad.write_text(json.dumps(historie, indent=1), encoding="utf-8")
    return historie


LETTERS = "ABCDEFG"


def verloop_html(historie: list) -> str:
    """Een kleine grafiek van de scores (zonder scripts), voor bovenaan het opgemaakte rapport."""
    import html as _h
    h = [x for x in historie if x.get("score") in LETTERS][-12:]
    if len(h) < 2:
        return ""
    kleur = {"A": "#1b7f3b", "B": "#4f9d2a", "C": "#a4b61f", "D": "#e0b400", "E": "#e98a15", "F": "#d9480f", "G": "#b1161a"}
    w, hg, px = 640, 170, 40
    stap = (w - 2 * px) / (len(h) - 1)
    y = lambda L: 18 + LETTERS.index(L) * (hg - 46) / 6  # noqa: E731
    pts = [(px + i * stap, y(x["score"])) for i, x in enumerate(h)]
    lijnen = "".join(f'<line x1="{px - 14}" x2="{w - px + 14}" y1="{y(L):.1f}" y2="{y(L):.1f}" stroke="#eef0f3"/>'
                     f'<text x="6" y="{y(L) + 4:.1f}" font-size="11" fill="#5b6676">{L}</text>' for L in LETTERS)
    pad = " ".join(f"{a:.1f},{b:.1f}" for a, b in pts)
    eendag = len({x["datum"][:10] for x in h}) == 1
    label = lambda x: x["datum"][11:16] if eendag else (x["datum"][8:10] + "-" + x["datum"][5:7])  # noqa: E731
    punten = "".join(f'<circle cx="{a:.1f}" cy="{b:.1f}" r="7" fill="{kleur[x["score"]]}"/>'
                     f'<text x="{a:.1f}" y="{hg - 8}" font-size="10" text-anchor="middle" fill="#5b6676">'
                     f'{_h.escape(label(x))}</text>' for (a, b), x in zip(pts, h))
    reeks = " → ".join(x["score"] for x in h)
    return (f'<div class="verloop"><b>Verloop van de scans:</b> {reeks}'
            f'<svg viewBox="0 0 {w} {hg}" width="100%" role="img" aria-label="Verloop: {reeks}">{lijnen}'
            f'<polyline points="{pad}" fill="none" stroke="#16202e" stroke-width="2"/>{punten}</svg></div>')


def rapport_in_repo(rap: dict, m: dict, letter: str, link: str | None = None, historie: list | None = None) -> str:
    """Zet .checkmijn/RAPPORT.md en rapport.json in de repository en commit ze met [skip ci] (geen nieuwe run)."""
    doel = PAD / RAPPORT_MAP
    doel.mkdir(exist_ok=True)
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


AUTOMATISCH = os.environ.get("CM_AUTOMATISCH", "nee").strip().lower() in ("ja", "true", "yes")


def alleen_handmatig() -> bool:
    """De scan draait alleen als de gebruiker hem zelf start (Run workflow), tenzij de workflow uitdrukkelijk
    'automatisch: ja' zet. Oudere workflowbestanden met push of schedule scannen dus niet meer vanzelf."""
    gebeurtenis = os.environ.get("GITHUB_EVENT_NAME", "")
    if gebeurtenis in ("", "workflow_dispatch") or AUTOMATISCH:
        return False
    tekst = ("**checkmijn.ai: deze scan is niet uitgevoerd.** De scan draait alleen als je hem zelf start, "
             "bij *Actions → checkmijn.ai → Run workflow*. Deze run kwam van '" + gebeurtenis + "'. "
             "Je project staat waarschijnlijk nog op een oudere versie van het bestand. Haal de nieuwste op via "
             "https://checkmijn.ai/scan.md (bouwtool: plak de tekst van checkmijn.ai/hoe-het-werkt opnieuw). "
             "Wil je toch automatisch scannen in je eigen pipeline, zet dan `automatisch: \"ja\"` bij de stap.")
    log(tekst.replace("**", ""))
    if SAMENVATTING:
        with open(SAMENVATTING, "a", encoding="utf-8") as f:
            f.write(tekst + "\n")
    return True


def main() -> int:
    if alleen_handmatig():
        return 0
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
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" in repo:
        cmd += ["--klant", repo.split("/")[0], "--app", repo.split("/")[1]]
    if nonce:
        cmd += ["--nonce", nonce]
    scan = subprocess.run(cmd, text=True)
    if scan.returncode not in (0, 2):
        sys.exit(f"checkmijn.ai: de scanner stopte met een fout (code {scan.returncode}).")

    rap = json.loads((OUT / "rapport.json").read_text())
    s = rap["samenvatting"]
    sc = s.get("score") or {}
    letter = nieuwe_letter(sc)
    regels = [
        "## checkmijn.ai — scanscore",
        "",
        f"**Score: {letter} · zelfscan · {dekking(sc)}** (hoogstens C; een keuring gaat tot A) · niveau {s.get('niveau', 1)} · dagversie {m['dagversie']} · commit `{(s.get('commit') or '')[:12]}`",
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
    stil = ongewijzigd_bij_dagscan(rap)
    terugzetten = rapport_in_repo_aan() and not stil
    historie = werk_historie_bij(rap, letter) if terugzetten else []
    grafiek = verloop_html(historie)
    if grafiek:
        p = OUT / "rapport.html"
        p.write_text(p.read_text(encoding="utf-8").replace("<!--checkmijn:verloop-->", grafiek, 1), encoding="utf-8")
    link = None
    if stil:
        regels += ["Dagelijkse controle: niets veranderd sinds de vorige scan, dus het rapport in de repository blijft staan.", ""]
    if RAPPORT_LINK and not stil:
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
    melding_lw = waarschuw(rap)
    if melding_lw:
        log(melding_lw)
        regels += [f"*{melding_lw}*", ""]
    if MEETELLEN:
        melding = meetellen(m, letter)
        log(melding)
        regels += [f"*{melding} Alleen de letter, voor de statistiek op checkmijn.ai/resultaten.*", ""]

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

    if terugzetten:
        regels += ["", rapport_in_repo(rap, m, letter, link, historie)]
    elif RAPPORT_IN_REPO == "auto" and not PRIVE:
        regels += ["", "Het rapport is niet in de repository gezet, omdat de repository openbaar is: dan zou iedereen de "
                   "bevindingen kunnen lezen."]
    schrijf_samenvatting("\n".join(regels))

    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"score={letter}\nrapport={OUT}\n")

    k, h = s["ernst"]["Kritiek"], s["ernst"]["Hoog"]
    if os.environ.get("CM_FAAL_LEK"):
        log("::error::checkmijn.ai lekkenwacht: kritieke of hoge lekken in componenten (zie de samenvatting van deze run).")
        return 1
    if (FAAL_BIJ == "kritiek" and k) or (FAAL_BIJ == "hoog" and (k or h)):
        log(f"::error::checkmijn.ai: {k} kritieke en {h} hoge bevinding(en).")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
