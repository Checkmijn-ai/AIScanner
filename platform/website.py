"""De website van checkmijn.ai: gewone HTML uit Jinja-templates, zonder trackers en met weinig JavaScript.

Dezelfde Flask-app serveert de API (api.checkmijn.ai) en de website (checkmijn.ai, test.checkmijn.ai).
Alle teksten staan in platform/templates/site/. De lijst van checks komt rechtstreeks uit aiscan/data/checks.yaml.
"""
from __future__ import annotations

import csv
import io
import json
import os
from functools import lru_cache
from pathlib import Path

import yaml
from flask import Blueprint, Response, abort, render_template, request, send_from_directory, url_for

ROOT = Path(__file__).resolve().parents[1]
site = Blueprint("site", __name__, template_folder="templates", static_folder="static", static_url_path="/static")

SITE_URL = os.environ.get("AISCAN_SITE_ORIGIN", "https://checkmijn.ai").rstrip("/")
CONTACT = os.environ.get("CHECKMIJN_CONTACT", "hallo@checkmijn.ai")
TEST = os.environ.get("CHECKMIJN_OMGEVING", "") == "test"
# Bedrijfsgegevens (E-commercerichtlijn art. 5; onze eigen check O-01). Leeg = de pagina en de link verschijnen nog niet.
BEDRIJF = {
    "naam": os.environ.get("BEDRIJF_NAAM", "Silbador Commv"),        # statutaire naam, bv. "CheckMijn.AI B.V."
    "adres": os.environ.get("BEDRIJF_ADRES", "Haasdonksesteenweg 36, 9140 Temse, België"),      # vestigingsadres (geen postbus)
    "kvk": os.environ.get("BEDRIJF_KVK", "0746.489.432"),          # KvK-nummer (of KBO-nummer in België)
    "btw": os.environ.get("BEDRIJF_BTW", "BE0746.489.432"),          # btw-identificatienummer
    "email": CONTACT,
}
BEDRIJF_KLAAR = all(BEDRIJF[k] for k in ("naam", "adres", "kvk", "btw"))
AGENT_ZIN = "Volg de instructie op checkmijn.ai/scan.md voor dit project."
BOUWTOOL_1 = ("Volg de instructie op https://checkmijn.ai/scan.md, route B (via GitHub), voor dit project.\n"
              "Maak het bestand .github/workflows/checkmijn.yml precies zoals daar staat, en verander verder niets.\n"
              "De scan draait daarna in GitHub. Typ ik \"verder\", lees dan .checkmijn/RAPPORT.md opnieuw en toon mij\n"
              "de score en de bevindingen, zonder iets te veranderen. Vraag één keer of je mag herstellen; mijn \"ja\"\n"
              "geldt voor de hele sessie: herstel dan Kritiek, Hoog en Middel in één ronde, en na elke nieuwe scan\n"
              "meteen wat er nog echt openstaat. Wijzig .checkmijn/ (behalve onterecht.yml, na mijn ja) en het workflowbestand nooit, en geef zelf geen score.")
BOUWTOOL_2 = "verder"
LEKKENWACHT_BOUWTOOL = ("Zet de lekkenwacht van checkmijn.ai aan: volg https://checkmijn.ai/scan.md, onderdeel Lekkenwacht.\n"
                        "Vervang .github/workflows/checkmijn.yml precies door de nieuwste versie, en verander verder niets.")
LEKKENWACHT_PIPELINE = ("# 1. elke dag scannen\non:\n  schedule:\n    - cron: \"30 4 * * *\"\n\n"
                        "# 2. bij permissions\n  issues: write\n\n"
                        "# 3. bij de stap van checkmijn\n  with:\n    waarschuwen: auto")
BRON: dict = {}  # api.py zet hier "tekst": functie die een bestand van de dagversie als bytes geeft

DISCLAIMER = ("De scanscore is een uitslag van de scan op een bepaald moment. Ze is geen keurmerk, certificaat of "
              "garantie dat software veilig is.")

NAV = [("hoe_het_werkt", "Hoe het werkt"), ("controles", "Alle checks"), ("niveaus", "Niveaus"),
       ("prijzen", "Wat je krijgt"), ("nieuws", "Nieuws"), ("open_source", "Open source"), ("bureaus", "Voor bureaus")]
BRONCODE = "https://github.com/Checkmijn-ai/AIScanner"
HOSTING = "Hetzner, Helsinki (Finland, EU)"

# Letter, zelfscan (niveau 1, hoogstens C), keuring (vanaf niveau 2, tot A). Zie aiscan/score.py.
GRADES = [
    ("A", "—", "Geen kritieke of hoge bevindingen, hoogstens 2 middelzware."),
    ("B", "—", "Geen kritieke of hoge bevindingen."),
    ("C", "Geen kritieke of hoge bevindingen. Het hoogste wat een zelfscan geeft.", "Geen kritieke, hoogstens 2 hoge bevindingen."),
    ("D", "Geen kritieke, hoogstens 2 hoge bevindingen.", "Geen kritieke, hoogstens 5 hoge bevindingen."),
    ("E", "Geen kritieke, hoogstens 5 hoge bevindingen.", "Hoogstens 1 kritieke bevinding."),
    ("F", "Hoogstens 1 kritieke bevinding.", "Hoogstens 3 kritieke bevindingen."),
    ("G", "2 of meer kritieke bevindingen.", "4 of meer kritieke bevindingen."),
]

LEVELS = [
    {"n": 1, "naam": "Basisscan", "status": "Nu, gratis", "voor": "Interne tools, kleine apps, een eerste meting",
     "wie": "Volledig automatisch", "checks": "45", "werkt": "—", "aanval": "—", "hoogste": "C",
     "geldig": "Zolang de scan actueel is"},
    {"n": 2, "naam": "Gekeurd", "status": "In voorbereiding (pilots)", "voor": "De meeste zakelijke apps",
     "wie": "Automatisch + erkende keurder", "checks": "±100, plus checks die je erbij kiest",
     "werkt": "Ja: functies doen wat ze beloven, negatieve tests op inloggen, rechten en invoer, scan van de draaiende app",
     "aanval": "14 gerichte aanvalstests op de meest voorkomende risico's", "hoogste": "A",
     "geldig": "12 maanden, met automatische checks bij elke release"},
    {"n": 3, "naam": "Gekeurd Plus", "status": "In voorbereiding (pilots)",
     "voor": "Aanbestedingen, veel persoonsgegevens, klanten onder NIS2", "wie": "Keurder + pentester",
     "checks": "Alles van niveau 2 + verplichte uitbreidingen", "werkt": "Ja, dieper, met een steekproef in de code",
     "aanval": "Handmatige pentest (vanaf 4 dagen) + hertest, door een CCV-gecertificeerd pentestbedrijf", "hoogste": "A", "geldig": "12 maanden"},
    {"n": 4, "naam": "Kritiek", "status": "Vanaf juli 2028",
     "voor": "Zorg, overheid, financiële sector (DORA), hoog-risico-AI", "wie": "Keurder + pentester, doorlopend",
     "checks": "Alles, met de strengste drempels", "werkt": "Ja: volledige review van de kritieke code",
     "aanval": "Pentest op aanvalsscenario's (vanaf 8 dagen), door een CCV-gecertificeerd pentestbedrijf", "hoogste": "A", "geldig": "12 maanden, doorlopend toezicht"},
]

ERKEND = ("Een erkende keurder is een IT-securityspecialist die door CheckMijn.AI erkend is: hij volgde onze opleiding, "
          "slaagde voor het examen, volgt elk jaar bijscholing en werkt volgens ons keurhandboek, met steekproeven op zijn werk. "
          "Hij keurt nooit een app die hij zelf herstelde of als klant aanbracht, en zijn vergoeding hangt nooit af van de uitslag. "
          "\"Erkend\" betekent erkend door CheckMijn.AI. Het is (nog) geen accreditatie door een overheidsinstantie zoals de RvA of "
          "BELAC. Later beheert een onafhankelijke organisatie de erkenning.")

FAQ = [
    ("Krijgen jullie mijn code?", "Nee. De scanner draait in je eigen GitHub of op je eigen machine. Wil je een "
     "scorepagina, dan stuur je alleen een bewijsbestand met per check de uitkomst, zonder code, paden of geheimen."),
    ("Ik bouw in Lovable, Bolt of v0. Kan ik scannen?", "Ja, via GitHub. Koppel je project aan een privé-repository en "
     "vraag je bouwtool om het workflowbestand van checkmijn.ai toe te voegen (zie Hoe het werkt). GitHub scant dan bij "
     "elke wijziging, en het rapport komt terug in je project. Je bouwtool toont eerst de score en een link naar het "
     "opgemaakte rapport, en herstelt pas na je akkoord."),
    ("Wat bewaren jullie van het rapport?", "Het opgemaakte rapport bewaren we versleuteld. De sleutel zit alleen in jouw "
     "persoonlijke link, na het #-teken, en komt nooit bij ons. Wij kunnen het dus niet lezen. Zonder account wissen we "
     "het na 90 dagen."),
    ("Moet ik iets installeren?", "Nee. Je AI-agent of je pipeline draait de scanner uit één bestand en ruimt daarna op."),
    ("Gebruiken jullie AI om te beoordelen?", "Nee. De meting gebruikt vaste regels: dezelfde code geeft altijd "
     "dezelfde uitkomst. AI mag je helpen herstellen, maar telt niet mee in de score."),
    ("Kan iemand vals spelen bij een zelfscan?", "Een zelfscan draait op een machine die wij niet controleren. "
     "Daarom staat er ZELFSCAN op de badge, met een gestippelde rand, en gaat de score hoogstens tot C. Wie zekerheid "
     "wil, kiest een keuring."),
    ("Is dit een certificaat?", "Nee, het is een onafhankelijke scanscore. Een officieel keurmerk komt er later, via een "
     "onafhankelijke organisatie, met deze scan als basis."),
    ("Wat is een erkende keurder?", ERKEND),
    ("Hoe echt is een zelfscan?", "We controleren dat het een echte, ondertekende scanner van die dag was, met een sessiecode "
     "die maar één keer werkt, en we rekenen de letter zelf na uit de resultaten. De uitvoering zelf zien we niet: wie zijn eigen "
     "omgeving beheert, kan een uitslag vervalsen. Daarom staat er ZELFSCAN op de badge en gaat de score hoogstens tot C. "
     "Vanaf niveau 2 draait een erkende keurder de scanner zelf, in jouw omgeving."),
    ("Wat betekent het percentage naast de letter?", "Hoeveel van de checks die op je app van toepassing zijn, echt gescand is, "
     "bv. \"C · zelfscan · 74% gecontroleerd\". Zonder URL van je live site kan de scanner bv. de headers en het certificaat niet "
     "nakijken. Onder 70% komt er geen letter. En zonder de kernchecks (geheimen in de code en pakketten met bekende lekken) "
     "geen hoogste letter."),
    ("Waarom haalt een zelfscan hoogstens een C?", "Een automatische scan ziet niet alles, en een zelfscan draait op een "
     "machine die wij niet zien. Zo verwart niemand een gratis C met een gekeurde C. Voor een A of B moet een erkende "
     "keurder hebben meegekeken."),
    ("Testen jullie ook of mijn app werkt?", "Vanaf niveau 2, samen met gerichte aanvalstests. Een volledige pentest zit "
     "in niveau 3."),
    ("Wie voert de pentest uit?", "Op niveau 3 en 4 voert een pentestbedrijf met het CCV Keurmerk Pentesten de handmatige "
     "pentest uit. Dat is het Nederlandse kwaliteitskeurmerk voor pentestbedrijven. De pentest volgt onze norm, zodat "
     "uitslagen vergelijkbaar zijn. De aanvalstests van niveau 2 zijn geautomatiseerd en voor iedereen dezelfde."),
    ("Welke programmeertalen?", "JavaScript/TypeScript en Python, met de populaire webframeworks. Meer volgt."),
    ("Hoe lang is een score geldig?", "Een scorepagina van een zelfscan blijft 30 dagen actueel; daarna wordt de badge "
     "grijs. Een scan bij elke wijziging houdt hem vanzelf actueel. Een keuring is 12 maanden geldig."),
    ("Controleren jullie of een tekst door AI geschreven is?", "Nee. We controleren software die met AI gebouwd is."),
]

BESTEK = ("De leverancier levert bij oplevering een scanscore van checkmijn.ai van C of beter op niveau 2, niet ouder "
          "dan 30 dagen.")


@lru_cache(maxsize=1)
def checks() -> list[dict]:
    data = yaml.safe_load((ROOT / "aiscan" / "data" / "checks.yaml").read_text(encoding="utf-8"))
    return [c for c in data if c.get("status", "actief") == "actief"]


@lru_cache(maxsize=1)
def norm() -> dict:
    """De volledige catalogus: alle checks van niveau 1 tot 4, plus de modules (norm/checks.yaml)."""
    return yaml.safe_load((ROOT / "norm" / "checks.yaml").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def bron_per_check() -> dict:
    """Welk bestand van de scanner een check uitvoert: {"E-05": ("aiscan/checks/secrets.py", 37), ...}."""
    import re
    uit = {}
    for f in sorted((ROOT / "aiscan" / "checks").glob("*.py")):
        for nr, regel in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            for cid in re.findall(r'@check\("([A-Z]-\d+)"', regel):
                uit.setdefault(cid, (f"aiscan/checks/{f.name}", nr))
    return uit


WAAROM = {
    "A": "Wie niet weet wat er in zijn software zit en welke AI erin gebruikt wordt, kan geen risico's inschatten of melden. De CRA en de AI Act vragen die inventaris.",
    "B": "Software die met AI gebouwd wordt, heeft eigen risico's: verzonnen pakketten, geheimen in agentbestanden, code die niemand nagelezen heeft.",
    "C": "Onleesbare of slordige code verbergt fouten en maakt herstel duur. Ook achtergebleven bestanden lekken soms gegevens.",
    "D": "Zonder automatische tests en beveiligingsscans in de pipeline glipt elke fout ongemerkt naar productie.",
    "E": "De klassieke lekken: inloggen, rechten, injectie, geheimen en versleuteling. Hier gaat het in de praktijk het vaakst mis.",
    "F": "Het grootste deel van moderne software bestaat uit pakketten van anderen. Eén lek daarin is een lek in jouw app.",
    "G": "De CRA verplicht fabrikanten om kwetsbaarheden te melden en updates te leveren. Daarvoor moet het proces er zijn.",
    "H": "Een AI-functie kan misleid worden (prompt injection), gegevens lekken of onverwacht duur worden.",
    "I": "Persoonsgegevens vragen bescherming volgens de AVG: scheiding tussen klanten, bewaartermijnen, toestemming.",
    "J": "Zonder documentatie kan niemand anders de software beheren, controleren of veilig overnemen.",
    "K": "Wat je niet ziet, kun je niet herstellen: logging, monitoring en een plan voor als het misgaat.",
    "L": "Software moet bruikbaar zijn voor iedereen. Voor overheden en vanaf 2025 voor veel webwinkels is toegankelijkheid verplicht.",
    "O": "De website is vaak de eerste indruk en de eerste ingang voor aanvallers: TLS, cookies, e-mailbeveiliging en de wettelijke gegevens.",
    "P": "Koppelingen met andere systemen zijn de deuren van je app. Elke deur heeft een slot en een logboek nodig.",
    "Q": "Wie mag wat veranderen, en wie keurt het goed? Zonder afspraken hangt beveiliging af van toeval.",
    "R": "Versiebeheer en vaste releases maken zichtbaar wat er in productie staat en wie wat veranderde.",
    "S": "Mobiele apps bewaren gegevens op het toestel en praten met servers via het internet: dat vraagt eigen controles.",
    "T": "Klassieke kwaliteitszorg: testen, foutenbeheer en acceptatie, ook als de code door AI geschreven is.",
    "U": "Alles wat in de browser staat, kan iedereen lezen. Geheimen, tokens en scripts van derden horen daar niet zomaar.",
    "W": "De databank en de opslag bevatten wat het meest waard is: gegevens van klanten. Die verdienen minimale rechten en versleuteling.",
    "X": "Hosting en cloud: wie beheert wat, waar staan de gegevens, en zijn de beheeraccounts goed beveiligd?",
    "Y": "Verouderde of onversleutelde protocollen zijn een open deur, ook als de app zelf goed gebouwd is.",
    "Z": "Software moet ook over vijf jaar nog te beheren, over te dragen en betaalbaar te houden zijn.",
}

NIVEAU_LABEL = {"verplicht": "●", "als van toepassing": "◐", "optioneel": "○", "niet": "–"}


@lru_cache(maxsize=1)
def workflow() -> str:
    return (ROOT / "voorbeelden" / "checkmijn.yml").read_text(encoding="utf-8")


@site.app_context_processor
def _algemeen():
    return {"NAV": NAV, "DISCLAIMER": DISCLAIMER, "CONTACT": CONTACT, "SITE_URL": SITE_URL, "TEST": TEST,
            "pad": request.path, "BRONCODE": BRONCODE, "ERKEND": ERKEND, "BEDRIJF": BEDRIJF, "BEDRIJF_KLAAR": BEDRIJF_KLAAR, "HOSTING": HOSTING, "dagkop": dagkop,
            "nieuws_vers": nieuws_vandaag(), "NB_ACTIEF": _nb_actief(), "getal": getal, "datum_nl": datum_nl}


def pagina(sjabloon: str, titel: str, beschrijving: str, **kw):
    return render_template(f"site/{sjabloon}", titel=titel, beschrijving=beschrijving, **kw)


@site.get("/")
def home():
    return pagina("home.html", "Onafhankelijke controle van software die met AI gebouwd is",
                  "Check je AI-software voor je ze lanceert, koopt of oplevert. Een meetlat, geen mening: 45 vaste "
                  "checks, Europese normen en een score van A tot G.", nieuws_kort=laatste_nieuws(),
                  teller=(lambda st: st if st.get("scans", 0) >= TOON_TELLER_VANAF else None)(statistiek()),
                  lekken=lekkendatabank())


@site.get("/hoe-het-werkt")
def hoe_het_werkt():
    return pagina("hoe-het-werkt.html", "Hoe het werkt",
                  "Scan met je AI-agent, via GitHub (ook voor Lovable, Bolt en v0) of laat keuren vanaf niveau 2.",
                  agent_zin=AGENT_ZIN, workflow=workflow(), bouwtool_1=BOUWTOOL_1, bouwtool_2=BOUWTOOL_2,
                  lw_bouwtool=LEKKENWACHT_BOUWTOOL, lw_pipeline=LEKKENWACHT_PIPELINE)


@site.get("/niveaus")
def niveaus():
    return pagina("niveaus.html", "Niveaus", "Hoe diep kijken we? Niveau 1 (Basisscan, nu gratis) tot niveau 4 (Kritiek).",
                  levels=LEVELS)


@site.get("/wat-we-controleren")
def controles():
    n = norm()
    cs = n["checks"]
    domeinen = sorted({c["domein"] for c in cs})
    tel = {k: sum(1 for c in cs if c["niveaus"][k] == "verplicht") for k in ("n1", "n2", "n3", "n4")}
    return pagina("controles.html", "Alle checks", f"Alle {len(cs)} checks van CheckMijn.AI, van niveau 1 tot 4: wat we "
                  "controleren, hoe, en volgens welke norm of wet.", checks=cs, domeinen=domeinen, tel=tel,
                  modules=n.get("modules", []), waarom=WAAROM, label=NIVEAU_LABEL, bron=bron_per_check())


@site.get("/check/<cid>")
def check_detail(cid):
    cs = {c["id"]: c for c in norm()["checks"]}
    c = cs.get(cid.upper())
    if not c:
        abort(404)
    if cid != c["id"]:
        from flask import redirect
        return redirect(url_for("site.check_detail", cid=c["id"]), 301)
    return pagina("check.html", f"{c['id']} · {c['wat'][:60]}", c["wat"], c=c, waarom=WAAROM.get(c["id"][0], ""),
                  bron=bron_per_check().get(c["id"]), label=NIVEAU_LABEL, levels=LEVELS)


@site.get("/open-source")
def open_source():
    return pagina("open-source.html", "Open source en transparant", "De scanner is open source (EUPL-1.2): lees "
                  "precies wat hij doet, controleer elke dagversie zelf, en zie wat er wel en niet naar buiten gaat.",
                  bron=bron_per_check(), n_checks=len(norm()["checks"]), geen_code=dagbestand("geen-code.json"))


def dagbestand(naam: str):
    """Een JSON-bestand van de dagversie (bv. geen-code.json, testbank.json), of None als het er (nog) niet is."""
    from werkzeug.exceptions import HTTPException
    try:
        return json.loads(BRON["tekst"](naam))
    except (HTTPException, ValueError, KeyError, OSError):
        return None


@site.get("/wat-je-krijgt")
def prijzen():
    return pagina("prijzen.html", "Wat je krijgt", "Per niveau precies wat je krijgt en wat het ongeveer kost.",
                  levels=LEVELS)


@site.get("/score-uitleg")
def score():
    return pagina("score.html", "De score", "Wat betekent de letter? De score van A tot G, de soorten scans en hoe een "
                  "score verloopt.", grades=GRADES)


@site.get("/waarom")
def waarom():
    return pagina("waarom.html", "Waarom een scan, en niet alleen een AI-review",
                  "Een AI-review geeft een mening. Onze scan is een meetlat.")


@site.get("/bureaus")
def bureaus():
    return pagina("bureaus.html", "Voor bureaus", "Lever bewijs mee bij elke oplevering: een onafhankelijke score en "
                  "rapport voor software die met AI gebouwd is.")


@site.get("/opdrachtgevers")
def opdrachtgevers():
    return pagina("opdrachtgevers.html", "Voor opdrachtgevers en inkopers", "Weet wat je leverancier oplevert: een "
                  "rapport dat je zonder IT-kennis begrijpt.", bestek=BESTEK)


@site.get("/vertrouwen")
def vertrouwen():
    return pagina("vertrouwen.html", "Vertrouwen en veiligheid", "Je code blijft bij jou, geen AI in de meting, elke "
                  "dagversie ondertekend, rapporten versleuteld.")


@site.get("/framework")
def framework():
    return pagina("framework.html", "Gratis framework", "De 45 checks als checklist, CSV of JSON, onder CC BY 4.0.",
                  checks=checks())


@site.get("/framework.md")
def framework_md():
    tekst = "# checkmijn.ai — framework (CC BY 4.0)\n\n" + "\n".join(
        f"- [ ] **{c['id']}** {c['scan']} ({c['normen']})" for c in checks()) + "\n"
    return Response(tekst, mimetype="text/markdown",
                    headers={"Content-Disposition": "attachment; filename=checkmijn-framework.md"})


@site.get("/framework.csv")
def framework_csv():
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["id", "domein", "scan", "normen", "ernst", "methode"])
    for c in checks():
        w.writerow([c["id"], c["domein"], c["scan"], c["normen"], c["ernst"], c.get("methode", "")])
    return Response("﻿" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=checkmijn-framework.csv"})


@site.get("/vragen")
def vragen():
    return pagina("vragen.html", "Veelgestelde vragen", "Antwoorden over code, rapporten, de score en de niveaus.", faq=FAQ)


@site.get("/privacy")
def privacy():
    return pagina("privacy.html", "Privacyverklaring", "Welke gegevens CheckMijn.AI verwerkt, waarom en hoe lang. Je code komt nooit bij ons.")


@site.get("/voorwaarden")
def voorwaarden():
    return pagina("voorwaarden.html", "Algemene voorwaarden", "De voorwaarden voor de scan, de scorepagina, de keuring en de pentest.")


@site.get("/bedrijfsgegevens")
def bedrijfsgegevens():
    if not BEDRIJF_KLAAR:
        abort(404)
    return pagina("bedrijfsgegevens.html", "Bedrijfsgegevens", "Wie achter CheckMijn.AI zit: naam, adres, ondernemingsnummer en btw-nummer.")


@site.get("/contact")
def contact():
    return pagina("contact.html", "Contact", "Plan een gesprek, word pilotklant of vraag een bureau-abonnement aan.")


@site.get("/scan")
def scan():
    return pagina("scan.html", "Scaninstructie (scan.md)", "De instructie die je AI-agent volgt om de scanner van "
                  "checkmijn.ai uit te voeren.", md=BRON["tekst"]("scan.md").decode("utf-8"), agent_zin=AGENT_ZIN, bouwtool_1=BOUWTOOL_1)


@site.get("/rapport/<rid>")
def rapport(rid):
    return pagina("rapport.html", "Scanrapport", "Versleuteld scanrapport.", rid=rid)


@site.get("/voorbeeldrapport")
def voorbeeldrapport():
    return send_from_directory(Path(site.static_folder), "voorbeeldrapport.html", mimetype="text/html")


@site.get("/norm/checks.yaml")
def norm_bestand():
    return send_from_directory(ROOT / "norm", "checks.yaml", mimetype="text/plain; charset=utf-8")


@site.get("/.well-known/security.txt")
def security_txt():
    tekst = ("Contact: mailto:security@checkmijn.ai\nExpires: 2027-10-20T00:00:00.000Z\nPreferred-Languages: nl, en\n"
             f"Canonical: {SITE_URL}/.well-known/security.txt\nPolicy: {SITE_URL}/vertrouwen\n")
    return Response(tekst, mimetype="text/plain")


# --- CRA ---------------------------------------------------------------------------------------------------
def cra_checks() -> list[dict]:
    import re as _re
    uit = []
    for c in norm()["checks"]:
        refs = [x.strip() for x in _re.split(r";", str(c.get("normen", ""))) if "CRA" in x]
        if not refs:
            continue
        niveau = next((int(k[1]) for k in ("n1", "n2", "n3", "n4") if c["niveaus"][k] == "verplicht"), None)
        uit.append({**c, "cra": _re.sub(r"\s+", " ", refs[0]).replace("CRA ", ""), "vanaf": niveau})
    return sorted(uit, key=lambda c: (c["vanaf"] or 9, c["id"]))


@site.get("/cra")
def cra():
    cs = cra_checks()
    per = {n: [c for c in cs if c["vanaf"] == n] for n in (1, 2, 3, 4)}
    return pagina("cra.html", "CheckMijn.AI en de Cyber Resilience Act",
                  "Helpt je CRA-dossier op orde te brengen en te houden. Wat de scan en de keuring wel en niet "
                  "doen voor de Europese Cyber Resilience Act.", checks=cs, per=per, totaal=len(norm()["checks"]))


# --- resultaten (openbare statistiek) -----------------------------------------------------------------------
TOON_TELLER_VANAF = int(os.environ.get("CHECKMIJN_TOON_TELLER_VANAF", "100"))


def statistiek() -> dict:
    import sys as _sys
    api = _sys.modules.get("api")
    try:
        return api.statistiek() if api else {}
    except Exception:
        return {}


def lekkendatabank() -> dict:
    """Aantal bekende lekken en de stand, uit het manifest van de dagversie van vandaag."""
    try:
        m = json.loads(BRON["tekst"]("latest.json"))
        return {"aantal": int(m["databank"]["aantal"]), "stand": m["databank"].get("stand", "")}
    except Exception:
        return {}


def getal(n) -> str:
    return "{:,}".format(int(n)).replace(",", ".")


def datum_nl(iso: str) -> str:
    from datetime import date
    try:
        d = date.fromisoformat(str(iso)[:10])
    except ValueError:
        return str(iso)
    return f"{d.day} {MAANDEN[d.month - 1]} {d.year}"


def _breedte(n: int, maximum: int) -> int:
    """Breedte in stappen van 5% (CSS-klassen b0..b100), want inline stijlen mogen niet (CSP)."""
    return 0 if not maximum else max(5 if n else 0, round(n / maximum * 20) * 5)


@site.get("/resultaten")
def resultaten():
    st = statistiek()
    return pagina("resultaten.html", "Resultaten",
                  "Werkt het? Hoeveel scans er gedaan zijn, en van welke score naar welke score projecten gingen na herstel.",
                  st=st, breedte=_breedte, letters="ABCDEFG")


# --- nieuws ------------------------------------------------------------------------------------------------
try:
    from zoneinfo import ZoneInfo
    NL_TZ = ZoneInfo("Europe/Amsterdam")
except Exception:  # pragma: no cover - zonder tijdzonegegevens
    from datetime import timezone as _tz
    NL_TZ = _tz.utc
DAGEN = ["maandag", "dinsdag", "woensdag", "donderdag", "vrijdag", "zaterdag", "zondag"]
MAANDEN = ["januari", "februari", "maart", "april", "mei", "juni", "juli", "augustus", "september", "oktober",
           "november", "december"]
_nieuws_cache: dict = {}


def nieuws_data() -> dict:
    import nieuws as nw
    try:
        mt = nw.PAD.stat().st_mtime
    except OSError:
        return {"bijgewerkt": None, "items": [], "bronnen": {}}
    if _nieuws_cache.get("mt") != mt:
        _nieuws_cache.update(mt=mt, d=nw.laad())
    return _nieuws_cache["d"]


def _lokaal(iso: str):
    from datetime import datetime
    return datetime.fromisoformat(iso).astimezone(NL_TZ)


def dagkop(iso: str) -> str:
    from datetime import datetime
    d = _lokaal(iso).date()
    vandaag = datetime.now(NL_TZ).date()
    if d == vandaag:
        return "Vandaag"
    if (vandaag - d).days == 1:
        return "Gisteren"
    return f"{DAGEN[d.weekday()]} {d.day} {MAANDEN[d.month - 1]}"


def tijdstip(iso: str | None) -> str:
    if not iso:
        return ""
    t = _lokaal(iso)
    return f"{dagkop(iso).lower() if dagkop(iso) in ('Vandaag', 'Gisteren') else dagkop(iso)} om {t:%H:%M}"


def domein_van(url: str) -> str:
    from urllib.parse import urlsplit
    return urlsplit(url).netloc.removeprefix("www.")


@site.get("/nieuws")
def nieuws():
    import nieuws as nw
    d = nieuws_data()
    per_tab = {}
    for t in nw.TABS:
        items = [i for i in d.get("items", []) if i["tab"] == t][:60]
        groepen: list[tuple[str, list]] = []
        for i in items:
            k = dagkop(i["datum"])
            if not groepen or groepen[-1][0] != k:
                groepen.append((k, []))
            groepen[-1][1].append(i)
        per_tab[t] = {"naam": nw.TABS[t], "aantal": len(items), "groepen": groepen}
    bronnen = [{"naam": b["naam"], "taal": b["taal"], "soort": b["soort"], "site": domein_van(b["url"]),
                "ok": d.get("bronnen", {}).get(b["naam"], {}).get("ok"),
                "fout": d.get("bronnen", {}).get(b["naam"], {}).get("fout", "")} for b in nw.BRONNEN]
    return pagina("nieuws.html", "Nieuws over AI en security",
                  "Dagelijks het belangrijkste nieuws over AI-security, cyberincidenten en AI, uit Nederlandse, Vlaamse "
                  "en Engelstalige bronnen. Drie keer per dag bijgewerkt, zonder dubbele berichten.",
                  tabs=per_tab, bijgewerkt=tijdstip(d.get("bijgewerkt")), bronnen=bronnen, ai_status=d.get("ai_status", {}),
                  tijd=lambda iso: f"{_lokaal(iso):%H:%M}", check_namen=nw.CHECK_NAMEN)


@site.get("/nieuws.xml")
def nieuws_rss():
    from email.utils import format_datetime
    from datetime import datetime
    from xml.sax.saxutils import escape
    import nieuws as nw
    d = nieuws_data()
    regels = []
    for i in d.get("items", [])[:80]:
        regels.append(
            "<item><title>{t}</title><link>{u}</link><guid isPermaLink=\"false\">checkmijn-{id}</guid>"
            "<pubDate>{p}</pubDate><category>{c}</category><source url=\"{su}\">{b}</source>"
            "<description>{s}</description></item>".format(
                t=escape(i["titel"]), u=escape(i["url"]), id=i["id"], p=format_datetime(datetime.fromisoformat(i["datum"])),
                c=escape(nw.TABS[i["tab"]]), su=escape(SITE_URL + "/nieuws"), b=escape(i["bron"]), s=escape(i.get("samenvatting", ""))))
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0"><channel><title>CheckMijn.AI nieuws</title>'
           f"<link>{SITE_URL}/nieuws</link><description>AI-security, cybersecurity en AI-nieuws, ontdubbeld.</description>"
           f"<language>nl</language>{''.join(regels)}</channel></rss>\n")
    return Response(xml, mimetype="application/rss+xml")


def laatste_nieuws(n: int = 3) -> list[dict]:
    """Voor de homepage: het belangrijkste van de laatste twee dagen (AI-security en NL/BE eerst)."""
    import nieuws_ai
    from datetime import datetime, timedelta, timezone
    items = nieuws_data().get("items", [])
    grens = datetime.now(timezone.utc) - timedelta(hours=48)
    recent = [i for i in items if datetime.fromisoformat(i["datum"]) >= grens] or items[:20]
    gekozen = sorted(recent, key=lambda i: (nieuws_ai.score(i), i["datum"]), reverse=True)[:n]
    return sorted(gekozen, key=lambda i: i["datum"], reverse=True)


def nieuws_vandaag() -> bool:
    from datetime import datetime
    items = nieuws_data().get("items", [])
    return bool(items) and _lokaal(items[0]["datum"]).date() == datetime.now(NL_TZ).date()


def _nb_actief() -> bool:
    import nieuwsbrief as nb
    return nb.actief()


# --- nieuwsbrief -------------------------------------------------------------------------------------------
_AANMELD: dict = {}


def _aanmeld_limiet(ip: str, max_per_uur: int = 5) -> bool:
    import time
    t = time.time()
    q = [x for x in _AANMELD.get(ip, []) if x > t - 3600]
    if len(q) >= max_per_uur:
        _AANMELD[ip] = q
        return False
    _AANMELD[ip] = q + [t]
    return True


@site.get("/nieuwsbrief")
def nieuwsbrief():
    import nieuwsbrief as nb
    staat = request.args.get("staat", "")
    if staat not in ("ok", "ongeldig", "uit", "fout", "te-vaak"):
        staat = ""
    return pagina("nieuwsbrief.html", "Nieuwsbrief",
                  "Elke week het belangrijkste nieuws over AI-security, cyberincidenten en AI, in vijf minuten. Gratis, "
                  "afmelden met één klik.", staat=staat, actief=nb.actief())


@site.post("/nieuwsbrief/aanmelden")
def nieuwsbrief_aanmelden():
    import nieuwsbrief as nb
    from flask import redirect
    ip = (request.headers.get("CF-Connecting-IP")
          or request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0]).strip()
    if request.form.get("website"):  # honingpot: mensen zien dit veld niet
        return redirect("/nieuwsbrief?staat=ok#aanmelden", 303)
    if not _aanmeld_limiet(ip):
        return redirect("/nieuwsbrief?staat=te-vaak#aanmelden", 303)
    staat = nb.aanmelden(request.form.get("email", ""))
    return redirect(f"/nieuwsbrief?staat={staat}#aanmelden", 303)


@site.get("/nieuwsbrief/bevestigd")
def nieuwsbrief_bevestigd():
    return pagina("nieuwsbrief.html", "Aangemeld", "Je bent aangemeld voor de nieuwsbrief.", staat="bevestigd", actief=True)


@site.get("/nieuwsbrief/voorbeeld")
def nieuwsbrief_voorbeeld():
    import nieuwsbrief as nb
    return Response(nb.html(nieuws_data(), voorbeeld=True), mimetype="text/html")


@site.get("/nieuws/post-van-de-dag")
def post_van_de_dag():
    from urllib.parse import quote
    posts = nieuws_data().get("posts", [])
    return pagina("posts.html", "Post van de dag", "", posts=posts, noindex=True,
                  deel=lambda t: "https://www.linkedin.com/feed/?shareActive=true&text=" + quote(t))


@site.get("/robots.txt")
def robots():
    if TEST:
        # Testomgeving: niet indexeren (elke pagina heeft ook noindex). /nieuws mag gelezen worden om de feeds te controleren.
        return Response("User-agent: *\nAllow: /nieuws\nDisallow: /\n", mimetype="text/plain")
    return Response(f"User-agent: *\nDisallow: /rapport/\nDisallow: /api/\nDisallow: /nieuws/post-van-de-dag\nDisallow: /nieuwsbrief/\nSitemap: {SITE_URL}/sitemap.xml\n",
                    mimetype="text/plain")


@site.get("/sitemap.xml")
def sitemap():
    paden = ["/", "/hoe-het-werkt", "/niveaus", "/wat-we-controleren", "/wat-je-krijgt", "/open-source", "/score-uitleg", "/waarom", "/bureaus",
             "/opdrachtgevers", "/vertrouwen", "/framework", "/vragen", "/contact", "/scan", "/nieuws", "/nieuwsbrief", "/resultaten", "/cra"]
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
           + "".join(f"  <url><loc>{SITE_URL}{p}</loc></url>\n" for p in paden)
           + "".join(f"  <url><loc>{SITE_URL}/check/{c['id']}</loc></url>\n" for c in norm()["checks"]) + "</urlset>\n")
    return Response(xml, mimetype="application/xml")


@site.get("/favicon.ico")
def favicon():
    return send_from_directory(Path(site.static_folder) / "img", "favicon.svg", mimetype="image/svg+xml")
