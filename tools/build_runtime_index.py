"""Haalt bij endoflife.date op welke versies van runtimes nog ondersteund worden, en wat de nieuwste versie per lijn is.

Gebruik: python tools/build_runtime_index.py <uitvoer.json>
Bron: https://endoflife.date (MIT). Mislukt het ophalen, dan blijft de vaste tabel in reference.yaml gelden.
"""
import json
import sys
import urllib.request

PRODUCTEN = {"node": "nodejs", "python": "python", "php": "php", "ruby": "ruby", "go": "go", "django": "django"}


def haal(product: str) -> list:
    req = urllib.request.Request(f"https://endoflife.date/api/{product}.json",
                                 headers={"User-Agent": "checkmijn.ai-dagversie (+https://checkmijn.ai)"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def bouw(doel: str) -> dict:
    uit = {"bron": "endoflife.date", "runtimes": {}}
    for naam, product in PRODUCTEN.items():
        try:
            lijnen = haal(product)
        except Exception as e:  # noqa: BLE001
            print(f"{product}: niet opgehaald ({e.__class__.__name__})", file=sys.stderr)
            continue
        t = {}
        for l in lijnen:
            eol = l.get("eol")
            t[str(l.get("cycle"))] = {"eol": eol if isinstance(eol, str) else (None if eol is False else "1970-01-01"),
                                      "laatste": str(l.get("latest") or ""), "datum": str(l.get("latestReleaseDate") or "")}
        uit["runtimes"][naam] = t
    with open(doel, "w") as f:
        json.dump(uit, f, indent=1)
    return uit


if __name__ == "__main__":
    d = bouw(sys.argv[1])
    print({k: len(v) for k, v in d["runtimes"].items()})
