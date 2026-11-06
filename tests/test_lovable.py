"""Verbeterpunten uit een testscan op een Lovable-project (6-11-2026):
- het workflowbestand van checkmijn.ai telt niet als 'de pipeline' (D-02, D-06);
- een lek in een ontwikkelafhankelijkheid zonder oplossing mag met een reden vastgelegd worden (F-01);
- C heet 'maximum zelfscan', en zonder W-13 staat 'onvolledig' bij de score."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from aiscan import score  # noqa: E402
from aiscan.core import Finding, Result  # noqa: E402
from aiscan.runner import onterecht_toepassen  # noqa: E402


def scan(bestanden: dict, checks: str) -> dict:
    tmp = Path(tempfile.mkdtemp())
    for naam, inhoud in bestanden.items():
        (tmp / naam).parent.mkdir(parents=True, exist_ok=True)
        (tmp / naam).write_text(inhoud)
    uit = tmp / "uit"
    subprocess.run([sys.executable, "-m", "aiscan", str(tmp), "--offline", "--alleen", checks, "--out", str(uit)],
                   cwd=ROOT, capture_output=True)
    return {c["id"]: c for c in json.loads((uit / "rapport.json").read_text())["checks"]}


eigen = (ROOT / "voorbeelden" / "checkmijn.yml").read_text()
r = scan({".github/workflows/checkmijn.yml": eigen, "package.json": "{}"}, "D-02,D-06")
for cid in ("D-02", "D-06"):
    titels = [b["titel"] for b in r[cid]["bevindingen"]]
    assert any("Geen pipeline gevonden" in t for t in titels), (cid, titels)          # alleen ons bestand = geen pipeline
    assert not any("checkmijn.yml" in (b.get("bestand") or "") for b in r[cid]["bevindingen"]), r[cid]

# F-01 in een ontwikkelafhankelijkheid: met reden vast te leggen; in productie niet
class P:  # klein nepproject met .checkmijn/onterecht.yml
    def __init__(self, root): self.root = root
tmp = Path(tempfile.mkdtemp()); (tmp / ".checkmijn").mkdir()
(tmp / ".checkmijn" / "onterecht.yml").write_text(
    "- check: F-01\n  bestand: package-lock.json\n  reden: esbuild via drizzle-kit, alleen de testserver, niet bereikbaar\n")
dev = Finding("F-01", "Middel", "esbuild 0.18.20: 1 bekende kwetsbaarheid (1 middel) · ontwikkelafhankelijkheid (telt één niveau lager) · indirect", "package-lock.json")
prod = Finding("F-01", "Middel", "axios 1.6.0: 1 bekende kwetsbaarheid (1 hoog)", "package-lock.json")
res = Result("F-01", status="Bevinding", findings=[dev, prod])
assert onterecht_toepassen(P(tmp), [({"id": "F-01"}, res)]) == 1
assert res.findings == [prod] and res.onterecht[0][0] is dev

# score: C als maximum zelfscan, en onvolledig zonder W-13
s = score.bereken([({"id": x}, Result(x)) for x in ("E-05", "F-01", "C-01", "C-06")]
                  + [({"id": "W-13"}, Result("W-13", status="Niet gescand"))], deel=False)
assert s["letter"] == "C" and s["onvolledig"] == ["W-13"], s
assert "maximum voor een zelfscan" in s["uitleg"] and "Onvolledig" in s["uitleg"], s["uitleg"]
print("ok: eigen workflow telt niet als pipeline, dev-lek met reden, C als maximum, onvolledig zonder W-13")
