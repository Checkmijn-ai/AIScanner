"""Scanscore A–G.

De letter telt per scan de zwaarste bevinding, niet het aantal bevindingen: tien lekken in één pakket wegen
zo niet zwaarder dan tien verschillende problemen. Een bevinding die nog bevestigd moet worden, telt één
ernstniveau lager tot een analist ze bevestigt.

Grenzen (aantal scans met als zwaarste bevinding ...):
  A  geen kritiek of hoog, hoogstens 2 middel           (alleen vanaf niveau 2)
  B  geen kritiek of hoog
  C  geen kritiek, hoogstens 2 hoog
  D  geen kritiek, hoogstens 5 hoog
  E  hoogstens 1 kritiek
  F  hoogstens 3 kritiek
  G  4 of meer kritiek
Niveau 1 (basisscan) haalt hoogstens een B. Een score komt er alleen als minstens 70% van de scans
die van toepassing zijn, ook echt gescand is.
"""
from __future__ import annotations

ORDE = {"Kritiek": 4, "Hoog": 3, "Middel": 2, "Laag": 1, "Info": 0}
NAAM = {4: "Kritiek", 3: "Hoog", 2: "Middel", 1: "Laag", 0: "Info"}
LETTERS = "ABCDEFG"
MIN_DEKKING = 0.70
GRENZEN = [
    ("A", "geen kritieke of hoge bevindingen, hoogstens 2 scans met een middelzware bevinding (alleen vanaf niveau 2)"),
    ("B", "geen kritieke of hoge bevindingen"),
    ("C", "geen kritieke bevindingen, hoogstens 2 scans met een hoge bevinding"),
    ("D", "geen kritieke bevindingen, hoogstens 5 scans met een hoge bevinding"),
    ("E", "hoogstens 1 scan met een kritieke bevinding"),
    ("F", "hoogstens 3 scans met een kritieke bevinding"),
    ("G", "4 of meer scans met een kritieke bevinding"),
]


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
    if k == 0 and h == 0 and m <= 2:
        letter = "A"
    elif k == 0 and h == 0:
        letter = "B"
    elif k == 0 and h <= 2:
        letter = "C"
    elif k == 0 and h <= 5:
        letter = "D"
    elif k <= 1:
        letter = "E"
    elif k <= 3:
        letter = "F"
    else:
        letter = "G"
    begrensd = False
    if niveau == 1 and letter == "A":
        letter, begrensd = "B", True
    toepasselijk = [r for _, r in results if r.status != "Niet van toepassing"]
    gescand = [r for r in toepasselijk if r.status in ("Gehaald", "Bevinding")]
    dekking = len(gescand) / len(toepasselijk) if toepasselijk else 0.0
    voldoende = dekking >= MIN_DEKKING
    if deel is None:
        deel = len(results) < 45  # met --alleen gedraaid: geen score
    if deel:
        voldoende = False
    return {
        "letter": letter if voldoende else None,
        "letter_als_volledig": letter,
        "dekking": round(dekking, 2),
        "voldoende_dekking": voldoende,
        "begrensd_door_niveau": begrensd,
        "scans_kritiek": k, "scans_hoog": h, "scans_middel": m,
        "grenzen": GRENZEN,
        "uitleg": (f"{k} scan(s) met een kritieke, {h} met een hoge en {m} met een middelzware bevinding als zwaarste."
                   + (" Niveau 1 haalt hoogstens een B." if begrensd else "")
                   + (f" Geen score: maar {len(results)} scans gedraaid, niet de volledige set." if deel else "")
                   + ("" if voldoende or deel else f" Geen score: maar {round(dekking * 100)}% van de scans die van toepassing zijn, "
                      f"is gescand (minimum {round(MIN_DEKKING * 100)}%). Scan met --url en --github-token voor een volledige score.")),
    }


def letter_uit(k: int, h: int, m: int, niveau: int = 1) -> str:
    if k == 0 and h == 0 and m <= 2:
        letter = "A"
    elif k == 0 and h == 0:
        letter = "B"
    elif k == 0 and h <= 2:
        letter = "C"
    elif k == 0 and h <= 5:
        letter = "D"
    elif k <= 1:
        letter = "E"
    elif k <= 3:
        letter = "F"
    else:
        letter = "G"
    return "B" if niveau == 1 and letter == "A" else letter


def uit_bewijs(resultaten: list, niveau: int = 1):
    """Herberekent de score uit een bewijsbestand (zoals de API dat doet)."""
    zw = [r.get("zwaarste") for r in resultaten]
    k, h, m = zw.count("Kritiek"), zw.count("Hoog"), zw.count("Middel")
    toep = [r for r in resultaten if r.get("status") != "Niet van toepassing"]
    gescand = [r for r in toep if r.get("status") in ("Gehaald", "Bevinding")]
    dekking = len(gescand) / len(toep) if toep else 0.0
    letter = letter_uit(k, h, m, niveau)
    return {"letter": letter if dekking >= MIN_DEKKING else None, "dekking": round(dekking, 2),
            "scans_kritiek": k, "scans_hoog": h, "scans_middel": m}
