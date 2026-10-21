"""Openbare statistiek: alleen echte GitHub-scans, alleen de letter, per project eerste en laatste score."""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
tmp = Path(tempfile.mkdtemp())
(tmp / "scan.md").write_text("# test\n")
os.environ.update({"AISCAN_DB": str(tmp / "t.db"), "AISCAN_PUBLIC": str(tmp), "CHECKMIJN_TOON_TELLER_VANAF": "5",
                   "CHECKMIJN_NIEUWS": str(tmp / "nieuws.json")})
os.environ.pop("AISCAN_PUBLIC_URL", None)
sys.path.insert(0, str(ROOT / "platform"))
import api  # noqa: E402

def nep_claims(token):
    if token == "fout":
        raise ValueError("ongeldig token")
    repo, _, event = token.partition(":")
    return {"repository_id": repo, "event_name": event or "push"}
api.oidc_claims = nep_claims
c = api.app.test_client()

def tel(repo, letter, event="push"):
    return c.post("/api/v1/telling", json={"letter": letter}, headers={"Authorization": f"Bearer {repo}:{event}"})

assert c.post("/api/v1/telling", json={"letter": "B"}).status_code == 401
assert c.post("/api/v1/telling", json={"letter": "B"}, headers={"Authorization": "Bearer fout"}).status_code == 401
assert tel("1", "Z").status_code == 422 and tel("1", "geen").status_code == 422
assert tel("1", "B", "pull_request").get_json()["geteld"] is False
assert tel("1", "B", "schedule").get_json()["geteld"] is False

# project 1: G → E → B; project 2: E → B; project 3: D (één keer); project 4: C → D (slechter)
for repo, letter in [("1", "G"), ("1", "E"), ("1", "B"), ("2", "E"), ("2", "B"), ("3", "D"), ("4", "C"), ("4", "D")]:
    assert tel(repo, letter).status_code == 201
s = api.app.test_request_context().__enter__() and api.statistiek()
assert s["scans"] == 8 and s["projecten"] == 4 and s["herhaald"] == 3, s
assert s["beter"] == 2 and s["slechter"] == 1 and s["gem_stappen"] == 4.0, s   # G→B = 5, E→B = 3
assert s["overgangen"][0][2] == 1 and ("G", "B", 1) in s["overgangen"] and ("C", "D", 1) in s["overgangen"]
assert s["eerste"] == {"G": 1, "E": 1, "D": 1, "C": 1}

# geen naam van de repository in de databank
import sqlite3  # noqa: E402
rij = sqlite3.connect(tmp / "t.db").execute("SELECT project FROM tel_projecten").fetchall()
assert all(len(r[0]) == 32 and r[0] not in ("1", "2", "3", "4") for r in rij)

# hoogstens 10 per project per dag
for _ in range(9):
    tel("5", "F")
assert tel("5", "F").status_code == 201 and tel("5", "F").get_json()["geteld"] is False

# zelfcontroles (AI-agent): tellen mee met een geldig bewijs, apart vermeld
echt = api.controleer_bewijs
api.controleer_bewijs = lambda b, voor_telling=False: (None, "2026-10-21", {"letter": b.get("letter")})
def zelf(projectcode, letter):
    return c.post("/api/v1/telling/zelf", json={"bewijs": {"nonce": "n", "letter": letter}, "project": projectcode})
assert zelf("geen-hex", "C").status_code == 422
assert zelf("a" * 64, "D").status_code == 201 and zelf("a" * 64, "B").status_code == 201
api.controleer_bewijs = echt
assert c.post("/api/v1/telling/zelf", json={"bewijs": {"formaat": "x"}, "project": "b" * 64}).status_code == 422
with api.app.test_request_context():
    s2 = api.statistiek()
assert s2["scans_zelf"] == 2 and s2["scans"] == s2["scans_github"] + 2, s2
assert s2["matrix"].get(("D", "B")) == 1

# pagina's
r = c.get("/resultaten").get_data(as_text=True)
assert "Van welk label naar welk label" in r and 'class="tabel matrix"' in r and 'style="' not in r
assert "scans sinds" in c.get("/").get_data(as_text=True)          # boven de drempel van 5
assert c.get("/api/v1/statistiek").get_json()["projecten"] == 6
print("ok: telling en resultaten")
