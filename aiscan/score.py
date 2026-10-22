"""Scanscore A–G.

De letter telt per scan de zwaarste bevinding, niet het aantal bevindingen: tien lekken in één pakket wegen
zo niet zwaarder dan tien verschillende problemen. Een bevinding die nog bevestigd moet worden, telt één
ernstniveau lager tot een analist ze bevestigt.

Er zijn twee schalen. Een zelfscan (niveau 1: de bouwer of zijn AI-agent draait de scanner zelf) haalt
hoogstens een C; een keuring (vanaf niveau 2, met een erkende keurder) gaat tot A. Zo verwart niemand een
gratis C met een gekeurde C: de badge van een zelfscan zegt er ook ZELFSCAN bij.

Grenzen (aantal scans met als zwaarste bevinding ...):
       zelfscan                         keuring
  A    -                                geen kritiek of hoog, hoogstens 2 middel
  B    -                                geen kritiek of hoog
  C    geen kritiek of hoog             geen kritiek, hoogstens 2 hoog
  D    geen kritiek, hoogstens 2 hoog   geen kritiek, hoogstens 5 hoog
  E    geen kritiek, hoogstens 5 hoog   hoogstens 1 kritiek
  F    hoogstens 1 kritiek              hoogstens 3 kritiek
  G    2 of meer kritiek                4 of meer kritiek
Een score komt er alleen als minstens 70% van de scans die van toepassing zijn, ook echt gescand is.
"""
from __future__ import annotations

ORDE = {"Kritiek": 4, "Hoog": 3, "Middel": 2, "Laag": 1, "Info": 0}
NAAM = {4: "Kritiek", 3: "Hoog", 2: "Middel", 1: "Laag", 0: "Info"}
LETTERS = "ABCDEFG"
MIN_DEKKING = 0.70
# Zonder deze checks geen hoogste letter: geheimen in de code (E-05) en pakketten met bekende lekken (F-01).
KERNCHECKS = ("E-05", "F-01")
GESCAND = ("Geen bevinding", "Gehaald", "Bevinding")
HOOGSTE_ZELFSCAN = "C"
GRENZEN_KEURING = [
    ("A", "geen kritieke of hoge bevindingen, hoogstens 2 scans met een middelzware bevinding"),
    ("B", "geen kritieke of hoge bevindingen"),
    ("C", "geen kritieke bevindingen, hoogstens 2 scans met een hoge bevinding"),
    ("D", "geen kritieke bevindingen, hoogstens 5 scans met een hoge bevinding"),
    ("E", "hoogstens 1 scan met een kritieke bevinding"),
    ("F", "hoogstens 3 scans met een kritieke bevinding"),
    ("G", "4 of meer scans met een kritieke bevinding"),
]
GRENZEN_ZELFSCAN = [
    ("C", "geen kritieke of hoge bevindingen (het hoogste wat een zelfscan geeft)"),
    ("D", "geen kritieke bevindingen, hoogstens 2 scans met een hoge bevinding"),
    ("E", "geen kritieke bevindingen, hoogstens 5 scans met een hoge bevinding"),
    ("F", "hoogstens 1 scan met een kritieke bevinding"),
    ("G", "2 of meer scans met een kritieke bevinding"),
]
GRENZEN = GRENZEN_ZELFSCAN  # de scanner in deze repository doet niveau 1: een zelfscan


def zelfscan(niveau: int) -> bool:
    return int(niveau or 1) < 2


def grenzen(niveau: int = 1):
    return GRENZEN_ZELFSCAN if zelfscan(niveau) else GRENZEN_KEURING


def zonder_kern(letter: str, ontbreekt: list, niveau: int = 1) -> str:
    """Ontbreekt een kerncheck, dan geen hoogste letter: hoogstens één letter lager."""
    if not ontbreekt or not letter:
        return letter
    plafond = "D" if zelfscan(niveau) else "C"
    return max(letter, plafond)  # verder in het alfabet = lager


def dekking_tekst(dekking) -> str:
    return f"{round((dekking or 0) * 100)}% gecontroleerd"


def letter_uit(k: int, h: int, m: int, niveau: int = 1) -> str:
    if zelfscan(niveau):
        if k == 0 and h == 0:
            return "C"
        if k == 0 and h <= 2:
            return "D"
        if k == 0 and h <= 5:
            return "E"
        return "F" if k <= 1 else "G"
    if k == 0 and h == 0:
        return "A" if m <= 2 else "B"
    if k == 0 and h <= 2:
        return "C"
    if k == 0 and h <= 5:
        return "D"
    if k <= 1:
        return "E"
    return "F" if k <= 3 else "G"


def oude_letter(k: int, h: int, m: int) -> str:
    """De letter van een zelfscan zoals scanners vóór 22 oktober 2026 hem gaven (hoogstens B).
    Alleen om bewijs van een oudere dagversie nog te aanvaarden; de API bewaart altijd de nieuwe letter."""
    if k == 0 and h == 0:
        return "B"
    if k == 0 and h <= 2:
        return "C"
    if k == 0 and h <= 5:
        return "D"
    return "E" if k <= 1 else ("F" if k <= 3 else "G")


# Oude zelfscanletter -> nieuwe: de grenzen schoven precies één letter op (F en G vallen samen in G).
OUD_NAAR_NIEUW = {"A": "C", "B": "C", "C": "D", "D": "E", "E": "F", "F": "G", "G": "G"}


def effectief(f) -> int:
    e = ORDE.get(f.ernst, 0)
    return max(e - 1, 0) if f.bevestigen else e


def bereken(results, niveau: int = 1, deel: bool | None = None):
    per_scan = {}
    for c, r in results:
        if r.findings:
            per_scan[c["id"]] = max(effectief(f) for f in r.findings)
    k = sum(1 for v in per_scan.values() if v == 4)
    h = sum(1 for v in per_scan.values() if v == 3)
    m = sum(1 for v in per_scan.values() if v == 2)
    status = {c["id"]: r.status for c, r in results}
    ontbreekt = [x for x in KERNCHECKS if x in status and status[x] not in GESCAND]
    letter = zonder_kern(letter_uit(k, h, m, niveau), ontbreekt, niveau)
    zelf = zelfscan(niveau)
    begrensd = zelf and letter == HOOGSTE_ZELFSCAN
    toepasselijk = [r for _, r in results if r.status != "Niet van toepassing"]
    gescand = [r for r in toepasselijk if r.status in ("Geen bevinding", "Bevinding")]
    dekking = len(gescand) / len(toepasselijk) if toepasselijk else 0.0
    voldoende = dekking >= MIN_DEKKING
    if deel is None:
        from .runner import load_checks  # noqa: PLC0415
        deel = len(results) < len(load_checks(1))  # met --alleen gedraaid: geen score
    if deel:
        voldoende = False
    return {
        "letter": letter if voldoende else None,
        "letter_als_volledig": letter,
        "dekking": round(dekking, 2),
        "voldoende_dekking": voldoende,
        "begrensd_door_niveau": begrensd,
        "zelfscan": zelf,
        "hoogste": HOOGSTE_ZELFSCAN if zelf else "A",
        "kern_ontbreekt": ontbreekt,
        "dekking_tekst": dekking_tekst(dekking),
        "scans_kritiek": k, "scans_hoog": h, "scans_middel": m,
        "grenzen": grenzen(niveau),
        "uitleg": (f"{k} scan(s) met een kritieke, {h} met een hoge en {m} met een middelzware bevinding als zwaarste."
                   + (" Een zelfscan haalt hoogstens een C; een keuring gaat tot A." if begrensd else "")
                   + (f" Geen hoogste letter: de kerncheck(s) {', '.join(ontbreekt)} zijn niet gescand." if ontbreekt else "")
                   + (f" Geen score: maar {len(results)} scans gedraaid, niet de volledige set." if deel else "")
                   + ("" if voldoende or deel else f" Geen score: maar {round(dekking * 100)}% van de scans die van toepassing zijn, "
                      f"is gescand (minimum {round(MIN_DEKKING * 100)}%). Scan met --url en --github-token voor een volledige score.")),
    }


def uit_bewijs(resultaten: list, niveau: int = 1):
    """Herberekent de score uit een bewijsbestand (zoals de API dat doet)."""
    # Per check telt alleen de zwaarste uitkomst, ook als een check (door een fout of geknoei) twee keer in het bewijs staat.
    per_check = {}
    for r in resultaten:
        e = ORDE.get(r.get("zwaarste"), -1)
        per_check[r.get("id")] = max(per_check.get(r.get("id"), -1), e)
    zw = list(per_check.values())
    k, h, m = zw.count(4), zw.count(3), zw.count(2)
    uniek = {}
    for r in resultaten:  # dekking: één status per check (de eerste)
        uniek.setdefault(r.get("id"), r)
    resultaten = list(uniek.values())
    toep = [r for r in resultaten if r.get("status") != "Niet van toepassing"]
    gescand = [r for r in toep if r.get("status") in GESCAND]
    dekking = len(gescand) / len(toep) if toep else 0.0
    status = {r.get("id"): r.get("status") for r in resultaten}
    ontbreekt = [x for x in KERNCHECKS if x in status and status[x] not in GESCAND]
    letter = zonder_kern(letter_uit(k, h, m, niveau), ontbreekt, niveau)
    return {"letter": letter if dekking >= MIN_DEKKING else None, "dekking": round(dekking, 2),
            "oude_letter": (oude_letter(k, h, m) if dekking >= MIN_DEKKING else None) if zelfscan(niveau) else None,
            "kern_ontbreekt": ontbreekt, "dekking_tekst": dekking_tekst(dekking),
            "zelfscan": zelfscan(niveau), "scans_kritiek": k, "scans_hoog": h, "scans_middel": m}
