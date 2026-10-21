"""Lekkenwacht in de GitHub Action: één issue bijhouden met kritieke en hoge lekken in componenten."""
import importlib.util
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
tmp = Path(tempfile.mkdtemp())
os.environ.update({"CM_PAD": str(tmp), "CM_OUT": str(tmp / "uit"), "GITHUB_REPOSITORY": "jan/app",
                   "GITHUB_EVENT_NAME": "schedule", "CM_PRIVE": "true", "CM_WAARSCHUWEN": "auto", "CM_TOKEN": "x",
                   "GITHUB_SERVER_URL": "https://github.com", "GITHUB_RUN_ID": "1"})
spec = importlib.util.spec_from_file_location("scan_ci", ROOT / "action" / "scan_ci.py")
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)


def rapport(*lekken):
    bev = [{"ernst": e, "titel": f"{n}: {k} bekende kwetsbaarheden (1 hoog) · indirect", "bestand": "bun.lock",
            "bewijs": f"GHSA-aaaa-bbbb-cccc (CVE-1): x · bijwerken naar minstens {naar}"} for n, k, e, naar in lekken]
    bev.append({"ernst": "Middel", "titel": "klein 1.0: 1 bekende kwetsbaarheid (1 middel)", "bewijs": ""})
    return {"checks": [{"id": "F-01", "bevindingen": bev}, {"id": "E-05", "bevindingen": [{"ernst": "Kritiek", "titel": "geheim"}]}],
            "samenvatting": {"ernst": {"Kritiek": 0, "Hoog": 1, "Middel": 0, "Laag": 0}, "commit": "abc"}}


# Nep-GitHub: houdt issues bij in het geheugen
issues, reacties = [], []
def nep_gh(methode, pad, data=None):
    if methode == "GET" and pad.startswith("/issues?"):
        return [i for i in issues if i["state"] == "open"]
    if methode == "POST" and pad == "/labels":
        return {}
    if methode == "POST" and pad == "/issues":
        i = {"number": len(issues) + 1, "state": "open", "body": data["body"], "title": data["title"]}
        issues.append(i)
        return i
    if methode == "POST" and pad.endswith("/comments"):
        reacties.append(data["body"])
        return {}
    if methode == "PATCH":
        n = int(pad.split("/")[2])
        issues[n - 1].update({k: v for k, v in data.items() if k in ("body", "state")})
        return {}
    raise AssertionError(pad)
sc._gh = nep_gh

# 1. alleen F-01 Kritiek/Hoog telt, geen geheimen of middelzware lekken
l = sc.lekken(rapport(("undici 7.24.8", 21, "Hoog", "7.29.1")))
assert len(l) == 1 and l[0]["sleutel"] == "undici 7.24.8#21" and l[0]["naar"] == "7.29.1" and l[0]["indirect"], l

# 2. eerste lek: issue geopend
m = sc.waarschuw(rapport(("undici 7.24.8", 21, "Hoog", "7.29.1")))
assert "issue #1 geopend" in m and issues[0]["state"] == "open" and "undici 7.24.8" in issues[0]["body"], m
assert "| undici 7.24.8 (indirect) | 21 | Hoog | 7.29.1 |" in issues[0]["body"]

# 3. dezelfde lekken de dag erna: niets nieuws, geen reactie
m = sc.waarschuw(rapport(("undici 7.24.8", 21, "Hoog", "7.29.1")))
assert "niets nieuws" in m and not reacties, m

# 4. nieuw lek (bv. vandaag in PHP-pakket): reactie op hetzelfde issue
m = sc.waarschuw(rapport(("undici 7.24.8", 21, "Hoog", "7.29.1"), ("php-pakket 2.0", 2, "Kritiek", "2.0.5")))
assert "1 nieuwe lekken" in m and len(reacties) == 1 and "php-pakket 2.0" in reacties[0] and len(issues) == 1, m

# 5. alles opgelost: issue gesloten
m = sc.waarschuw(rapport())
assert "gesloten" in m and issues[0]["state"] == "closed", m

# 6. openbare repository: geen issue, de run moet mislukken
sc.PRIVE = False
n = len(issues)
m = sc.waarschuw(rapport(("undici 7.24.8", 21, "Hoog", "7.29.1")))
assert len(issues) == n and os.environ.get("CM_FAAL_LEK") == "1" and "mislukt" in m, m
os.environ.pop("CM_FAAL_LEK")

# 7. uit, of bij een pull request: niets
sc.WAARSCHUWEN = "nee"
assert sc.waarschuw(rapport(("x 1", 1, "Hoog", "2"))) == ""
sc.WAARSCHUWEN = "auto"
os.environ["GITHUB_EVENT_NAME"] = "pull_request"
assert sc.waarschuw(rapport(("x 1", 1, "Hoog", "2"))) == ""

# 8. dagscan zonder verschil: niets terugzetten
os.environ["GITHUB_EVENT_NAME"] = "schedule"
(tmp / ".checkmijn").mkdir(exist_ok=True)
(tmp / ".checkmijn" / "historie.json").write_text('[{"commit": "abc", "k": 0, "h": 1, "m": 0, "l": 0}]')
assert sc.ongewijzigd_bij_dagscan(rapport(("undici 7.24.8", 21, "Hoog", "7.29.1")))
os.environ["GITHUB_EVENT_NAME"] = "push"
assert not sc.ongewijzigd_bij_dagscan(rapport())
print("ok: lekkenwacht")
