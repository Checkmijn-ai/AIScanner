"""H-29 en H-31: agents die zelf handelen, en code die een agent uitvoert."""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "tests" / "data_agents"


def scan(bestand, naam):
    d = Path(tempfile.mkdtemp())
    shutil.copy(DATA / bestand, d / naam)
    uit = d / "uit"
    subprocess.run([sys.executable, "-m", "aiscan", str(d), "--offline", "--alleen", "H-29,H-31", "--out", str(uit)], cwd=ROOT,
                   capture_output=True)
    return {c["id"]: c for c in json.loads((uit / "rapport.json").read_text())["checks"]}


def kort(c):
    return sorted((b["ernst"], b["bevestigen"], b["regel"]) for b in c["bevindingen"])


# Terugbetalen zonder bevestiging, een shelltool en een Python-REPL op de server
c = scan("onveilig.py.txt", "agent.py")
assert kort(c["H-29"]) == [("Hoog", True, 6)], c["H-29"]
assert kort(c["H-31"]) == [("Hoog", False, 12), ("Hoog", False, 22)], c["H-31"]
assert any("refund (betalen)" in i for i in c["H-29"]["info"]), c["H-29"]["info"]

# Verwijderen met needsApproval: geen bevinding
c = scan("bevestigd.ts.txt", "agent.ts")
assert c["H-29"]["status"] == "Geen bevinding" and not c["H-29"]["bevindingen"], c["H-29"]
assert c["H-31"]["status"] == "Niet van toepassing", c["H-31"]

# Code in een E2B-sandbox: geen bevinding
c = scan("sandbox.py.txt", "agent.py")
assert not c["H-29"]["bevindingen"] and not c["H-31"]["bevindingen"], c

# Geen agent: niet van toepassing
d = Path(tempfile.mkdtemp())
(d / "app.py").write_text("from openai import OpenAI\nc = OpenAI()\nc.chat.completions.create(model='x', messages=[], max_tokens=5)\n")
subprocess.run([sys.executable, "-m", "aiscan", str(d), "--offline", "--alleen", "H-29,H-31", "--out", str(d / "uit")], cwd=ROOT,
               capture_output=True)
for x in json.loads((d / "uit" / "rapport.json").read_text())["checks"]:
    assert x["status"] == "Niet van toepassing", x
print("agents ok")
