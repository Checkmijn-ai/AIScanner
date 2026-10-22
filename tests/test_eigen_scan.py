"""Wat de scan op de eigen code onterecht meldde (22 oktober 2026): publieke sleutel, treffers in tekst, tests als script,
time-out als variabele. En wat wel gemeld moet blijven."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
tmp = Path(tempfile.mkdtemp())
(tmp / "public-key.pem").write_text("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAabc=\n-----END PUBLIC KEY-----\n")
(tmp / "server.key").write_text("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIabc=\n-----END PRIVATE KEY-----\n")
(tmp / "regels.py").write_text('''import requests, ssl
UITLEG = "eval() of exec() met een variabele; zet nooit CERT_NONE"
def haal(url, t):
    return requests.get("https://x.invalid/" + url.replace("/", "%2F"), timeout=t).json()
def slecht(x):
    eval(x)
    ctx = ssl.create_default_context()
    ctx.verify_mode = ssl.CERT_NONE
    return requests.get(x)
''')
wf = tmp / ".github" / "workflows"
wf.mkdir(parents=True)
(wf / "tests.yml").write_text("on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: python tests/test_demo.py\n")
subprocess.run(["git", "init", "-q"], cwd=tmp)
subprocess.run(["git", "add", "-A"], cwd=tmp)
uit = tmp / "uit"
subprocess.run([sys.executable, "-m", "aiscan", str(tmp), "--offline", "--out", str(uit)], cwd=ROOT, capture_output=True)
d = json.loads((uit / "rapport.json").read_text())
b = [(c["id"], x["bestand"], x["regel"], x["titel"]) for c in d["checks"] for x in c["bevindingen"]]
assert not any(t[0] == "C-20" and t[1] == "public-key.pem" for t in b), b      # publieke sleutel: geen geheim
assert any(t[0] == "C-20" and t[1] == "server.key" for t in b), b              # privésleutel: wel
assert not any(t[1] == "regels.py" and t[2] == 2 for t in b), b                # alleen tekst
assert any(t[0] == "C-01" and t[2] == 6 for t in b), b                         # echte eval
assert any(t[0] == "E-06" and t[2] == 8 for t in b), b                         # echte CERT_NONE
assert not any(t[0] == "W-06" and t[2] == 4 for t in b), b                     # time-out als variabele
assert any(t[0] == "W-06" and t[2] == 9 for t in b), b                         # zonder time-out
assert not any(t[0] == "D-02" and "geen tests" in t[3] for t in b), b          # python tests/... telt als test
print("ok: eigen scan zonder onterechte meldingen")
