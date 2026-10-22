"""Scanscore: twee schalen (zelfscan tot C, keuring tot A) en een dubbele check telt maar één keer."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aiscan.score import OUD_NAAR_NIEUW, letter_uit, oude_letter, uit_bewijs  # noqa: E402

# zelfscan (niveau 1): hoogstens C
assert [letter_uit(k, h, 0, 1) for k, h in [(0, 0), (0, 2), (0, 5), (1, 0), (2, 0)]] == list("CDEFG")
# keuring (niveau 2+): tot A
assert [letter_uit(k, h, m, 2) for k, h, m in [(0, 0, 2), (0, 0, 3), (0, 2, 0), (0, 5, 0), (1, 0, 0), (3, 0, 0), (4, 0, 0)]] == list("ABCDEFG")
# de oude letter zet precies om naar de nieuwe
for k in range(6):
    for h in range(8):
        assert OUD_NAAR_NIEUW[oude_letter(k, h, 0)] == letter_uit(k, h, 0, 1), (k, h)

# een check die twee keer in het bewijs staat, telt één keer, met zijn zwaarste uitkomst
res = [{"id": "A-01", "status": "Bevinding", "zwaarste": "Hoog"}, {"id": "A-01", "status": "Bevinding", "zwaarste": "Hoog"},
       {"id": "A-02", "status": "Bevinding", "zwaarste": "Middel"}, {"id": "A-02", "status": "Bevinding", "zwaarste": "Kritiek"},
       {"id": "A-03", "status": "Geen bevinding", "zwaarste": None}]
s = uit_bewijs(res)
assert (s["scans_kritiek"], s["scans_hoog"], s["scans_middel"]) == (1, 1, 0) and s["letter"] == "F" and s["dekking"] == 1.0, s
print("ok: score")
