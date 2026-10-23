"""R-14: de OTAP-route, uit de pipeline en de geschiedenis van de productiebranch."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "GIT_AUTHOR_NAME": "Mens", "GIT_AUTHOR_EMAIL": "m@example.invalid", "GIT_COMMITTER_NAME": "Mens",
       "GIT_COMMITTER_EMAIL": "m@example.invalid"}


def repo(commits, workflow=None):
    d = Path(tempfile.mkdtemp())
    g = lambda *a, env=ENV: subprocess.run(["git", "-C", str(d), *a], check=True, capture_output=True, env=env)  # noqa: E731
    g("init", "-q", "-b", "main")
    if workflow:
        (d / ".github" / "workflows").mkdir(parents=True)
        (d / ".github" / "workflows" / "uitrol.yml").write_text(workflow)
    for i, (onderwerp, auteur) in enumerate(commits):
        (d / f"f{i}.txt").write_text(str(i))
        g("add", "-A")
        g("commit", "-q", "-m", onderwerp, env={**ENV, "GIT_AUTHOR_NAME": auteur, "GIT_COMMITTER_NAME": auteur})
    uit = d / "uit"
    subprocess.run([sys.executable, "-m", "aiscan", str(d), "--offline", "--alleen", "R-14", "--out", str(uit)], cwd=ROOT,
                   capture_output=True)
    return next(c for c in json.loads((uit / "rapport.json").read_text())["checks"] if c["id"] == "R-14")


# Lovable-achtig: alles rechtstreeks op main, geen testomgeving -> Hoog
c = repo([(f"Wijziging {i}", "gpt-engineer-app[bot]") for i in range(8)])
assert [(b["ernst"], b["bevestigen"]) for b in c["bevindingen"]] == [("Hoog", False)], c
# Met een testomgeving in de pipeline, maar soms rechtstreeks -> Middel om na te kijken
wf = "on:\n  push:\n    branches: [main, test]\njobs:\n  u:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ssh server ./uitrol.sh\n"
c = repo([(f"Wijziging {i} (#{i})", "Mens") for i in range(6)] + [("Snel iets", "Mens")], wf)
assert [(b["ernst"], b["bevestigen"]) for b in c["bevindingen"]] == [("Middel", True)], c
# Alles via pull requests en een testomgeving -> geen bevinding
c = repo([(f"Wijziging {i} (#{i})", "Mens") for i in range(6)], wf)
assert c["status"] == "Geen bevinding" and not c["bevindingen"], c
# Scanrapporten van de action tellen niet mee
c = repo([(f"Wijziging {i} (#{i})", "Mens") for i in range(6)] + [("checkmijn.ai: scanrapport (C) [skip ci]", "checkmijn.ai")], wf)
assert not c["bevindingen"], c
print("ok: OTAP-route (R-14)")
