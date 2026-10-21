"""De wekelijkse nieuwsbrief van CheckMijn.AI, via Brevo (Frankrijk, EU).

- Aanmelden op de site gaat met dubbele bevestiging (double opt-in): Brevo stuurt een mail, pas na de klik staat
  iemand op de lijst. Afmelden kan met één klik onderaan elke nieuwsbrief.
- Elke maandagochtend maakt de server een CONCEPT in Brevo met het belangrijkste nieuws van de week.
  Jij bekijkt het in Brevo en drukt zelf op verzenden.

    python /app/platform/nieuwsbrief.py concept     # concept in Brevo zetten
    python /app/platform/nieuwsbrief.py voorbeeld   # de HTML op het scherm

Instellingen (omgevingsvariabelen, op de server in /etc/checkmijn/geheimen.env):
    BREVO_API_KEY           API-sleutel van Brevo (geheim)
    BREVO_LIJST             nummer van de contactlijst "Nieuwsbrief"
    BREVO_DOI_TEMPLATE      nummer van de bevestigingsmail (sjabloon met de tag "optin")
    NIEUWSBRIEF_AFZENDER    afzender, bv. nieuws@checkmijn.ai (moet in Brevo geverifieerd zijn)
"""
from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

BREVO = "https://api.brevo.com/v3"
SITE = os.environ.get("AISCAN_SITE_ORIGIN", "https://checkmijn.ai").rstrip("/")
EMAIL_RX = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$")


def instellingen() -> dict:
    def getal(naam):
        try:
            return int(os.environ.get(naam, "").strip())
        except ValueError:
            return None
    return {"sleutel": os.environ.get("BREVO_API_KEY", "").strip(), "lijst": getal("BREVO_LIJST"),
            "doi": getal("BREVO_DOI_TEMPLATE"),
            "afzender": os.environ.get("NIEUWSBRIEF_AFZENDER", "nieuws@checkmijn.ai").strip()}


def actief() -> bool:
    i = instellingen()
    return bool(i["sleutel"] and i["lijst"] and i["doi"])


def _brevo(methode: str, pad: str, json=None):
    import requests

    r = requests.request(methode, BREVO + pad, timeout=20, json=json,
                         headers={"api-key": instellingen()["sleutel"], "accept": "application/json"})
    return r


def aanmelden(email: str) -> str:
    """Geeft 'ok', 'ongeldig', 'uit' of 'fout'. Ook een bestaand adres geeft 'ok' (we verraden niet wie er op de lijst staat)."""
    email = (email or "").strip()
    if not EMAIL_RX.match(email):
        return "ongeldig"
    if not actief():
        return "uit"
    i = instellingen()
    try:
        r = _brevo("POST", "/contacts/doubleOptinConfirmation", {
            "email": email, "includeListIds": [i["lijst"]], "templateId": i["doi"],
            "redirectionUrl": f"{SITE}/nieuwsbrief/bevestigd"})
    except Exception:
        return "fout"
    if r.status_code in (201, 204) or (r.status_code == 400 and "already" in r.text.lower()):
        return "ok"
    print(f"Brevo aanmelden: {r.status_code} {r.text[:200]}", file=sys.stderr)
    return "fout"


# --- inhoud ------------------------------------------------------------------------------------------------
def inhoud(d: dict, nu: datetime | None = None) -> dict:
    import nieuws_ai

    nu = nu or datetime.now(timezone.utc)
    week = [i for i in d.get("items", []) if datetime.fromisoformat(i["datum"]) >= nu - timedelta(days=7)]
    def top(tab, n):
        return sorted((i for i in week if i["tab"] == tab), key=lambda i: (nieuws_ai.score(i), i["datum"]), reverse=True)[:n]
    tot = nu.astimezone(nieuws_ai.NL_TZ)
    van = tot - timedelta(days=6)
    maanden = ["januari", "februari", "maart", "april", "mei", "juni", "juli", "augustus", "september", "oktober",
               "november", "december"]
    periode = (f"{van.day} {maanden[van.month - 1]}" if van.month != tot.month else f"{van.day}") + \
              f" tot {tot.day} {maanden[tot.month - 1]} {tot.year}"
    return {"periode": periode, "secties": [
        ("AI-security", "Lekken en aanvallen via AI, en AI-agents die hun boekje te buiten gaan.", top("ai-security", 5)),
        ("Cyberincidenten", "Hacks, datalekken en lekken die je nu moet dichten.", top("cyber", 3)),
        ("AI-nieuws", "Wat er verder gebeurde in de wereld van AI.", top("ai", 2)),
    ], "site": SITE}


def html(d: dict, nu: datetime | None = None, voorbeeld: bool = False) -> str:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    import nieuws as nw

    env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"), autoescape=select_autoescape(["html"]))
    return env.get_template("nieuwsbrief/mail.html").render(**inhoud(d, nu), check_namen=nw.CHECK_NAMEN,
                                                           afmelden="#" if voorbeeld else "{{ unsubscribe }}")


def concept(d: dict, nu: datetime | None = None) -> str:
    """Zet de nieuwsbrief van deze week als concept in Brevo. Versturen doe je zelf in Brevo."""
    if not actief():
        return "Brevo is nog niet ingesteld (BREVO_API_KEY, BREVO_LIJST, BREVO_DOI_TEMPLATE)."
    i = instellingen()
    c = inhoud(d, nu)
    eerste = next((s[2][0] for s in c["secties"] if s[2]), None)
    onderwerp = f"AI en security deze week: {eerste['titel'][:70]}" if eerste else "AI en security deze week"
    r = _brevo("POST", "/emailCampaigns", {
        "name": f"Nieuwsbrief {c['periode']}", "subject": onderwerp,
        "previewText": "Het belangrijkste nieuws over AI-security, cyberincidenten en AI, in vijf minuten.",
        "sender": {"name": "CheckMijn.AI", "email": i["afzender"]},
        "htmlContent": html(d, nu), "recipients": {"listIds": [i["lijst"]]}})
    if r.status_code >= 300:
        return f"Brevo gaf {r.status_code}: {r.text[:300]}"
    return f"Concept klaar in Brevo (campagne {r.json().get('id')}): {onderwerp}"


def main(argv=None) -> int:
    import nieuws as nw

    argv = argv if argv is not None else sys.argv[1:]
    d = nw.laad()
    if argv[:1] == ["voorbeeld"]:
        print(html(d, voorbeeld=True))
    elif argv[:1] == ["concept"]:
        print(concept(d))
    else:
        print(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main())
