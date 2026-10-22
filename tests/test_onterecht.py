"""Onterecht gemeld: alleen meldingen 'nakijken' kunnen weg, met een reden, en ze blijven zichtbaar in het rapport."""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from aiscan.core import Finding, Project, Result  # noqa: E402
from aiscan.runner import onterecht_toepassen, to_json  # noqa: E402
from aiscan.score import bereken  # noqa: E402

tmp = Path(tempfile.mkdtemp())
(tmp / ".checkmijn").mkdir()
(tmp / ".checkmijn" / "onterecht.yml").write_text("""
- check: U-07
  bestand: src/i18n.ts
  regel: 12
  reden: HTML uit onze eigen vertalingen
- check: E-05
  bestand: src/config.ts
  reden: probeert een zekere bevinding weg te zetten
- check: U-07
  bestand: src/ander.ts
""")
proj = Project(str(tmp))

def res(cid, *fs):
    r = Result(cid)
    for f in fs:
        r.add(f)
    r.status = "Bevinding"
    return {"id": cid, "domein": "x", "scan": "x", "normen": "x", "methode": "x", "ernst": "Hoog"}, r

results = [
    res("U-07", Finding("U-07", "Hoog", "innerHTML", "src/i18n.ts", 12, bevestigen=True),
        Finding("U-07", "Hoog", "innerHTML", "src/ander.ts", 3, bevestigen=True)),   # tweede: regel zonder reden telt niet
    res("E-05", Finding("E-05", "Kritiek", "Sleutel in code", "src/config.ts", 4)),  # zeker: blijft altijd
    res("C-01", Finding("C-01", "Hoog", "x", "src/i18n.ts", 12, bevestigen=True)),   # andere check: blijft
]
assert onterecht_toepassen(proj, results) == 1
u07, e05, c01 = (r for _, r in results)
assert len(u07.onterecht) == 1 and u07.onterecht[0][1] == "HTML uit onze eigen vertalingen"
assert [f.bestand for f in u07.findings] == ["src/ander.ts"] and u07.status == "Bevinding"
assert len(e05.findings) == 1 and not e05.onterecht and len(c01.findings) == 1

# als alle meldingen van een check onterecht zijn, is de check 'Geen bevinding'
results2 = [res("U-07", Finding("U-07", "Hoog", "innerHTML", "./src/i18n.ts", 12, bevestigen=True))]
onterecht_toepassen(proj, results2)
assert results2[0][1].status == "Geen bevinding"
j = to_json({"score": bereken(results2)}, results2)
assert j["checks"][0]["onterecht"][0]["reden"] == "HTML uit onze eigen vertalingen"
print("ok: onterecht gemeld")
