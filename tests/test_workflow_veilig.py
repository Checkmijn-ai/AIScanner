"""De voorbeeldbestanden voor GitHub moeten veilig blijven: alleen handmatig starten, een vaste versie
(volledige commit), zo weinig rechten als kan, en niets dat vanzelf iets naar buiten stuurt."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VB = ROOT / "voorbeelden"


def regels(naam):
    return (VB / naam).read_text(encoding="utf-8")


def code(tekst):
    return "\n".join(r.split("#", 1)[0].rstrip() for r in tekst.splitlines() if not r.lstrip().startswith("#"))


for naam in ("checkmijn.yml", "checkmijn-schrijven.yml"):
    t = code(regels(naam))
    on = t[t.index("\non:"):t.index("\npermissions:")]
    assert "workflow_dispatch" in on, naam
    for verboden in ("push", "schedule", "pull_request", "workflow_run", "cron"):
        assert verboden not in on, (naam, verboden)
    assert "issues:" not in t, naam
    m = re.search(r"uses: Checkmijn-ai/AIScanner@(\S+)", t)
    assert m and re.fullmatch(r"[0-9a-f]{40}", m.group(1)), (naam, "geen volledige commit")
    for uses in re.findall(r"uses: (\S+)", t):
        assert re.search(r"@[0-9a-f]{40}$", uses), (naam, uses, "niet vastgezet")
    assert 'meetellen: "false"' in t and 'waarschuwen: "nee"' in t and 'insturen: "false"' in t, naam

lezen = code(regels("checkmijn.yml"))
assert "contents: read" in lezen and "contents: write" not in lezen
assert "persist-credentials: false" in lezen
assert 'rapport-in-repo: "false"' in lezen
schrijven = code(regels("checkmijn-schrijven.yml"))
assert "contents: write" in schrijven and "rapport-in-repo: auto" in schrijven

# dezelfde vaste versie in beide bestanden
v = {re.search(r"AIScanner@([0-9a-f]{40})", code(regels(n))).group(1) for n in ("checkmijn.yml", "checkmijn-schrijven.yml")}
assert len(v) == 1, v

# scan.md toont beide bestanden en zet nooit zelf een automatische scan
tpl = (ROOT / "platform" / "templates" / "scan.md.j2").read_text(encoding="utf-8")
assert "{{ workflow }}" in tpl and "{{ workflow_schrijven }}" in tpl
assert "Run workflow" in tpl and "B8. Opruimen" in tpl
# GitLab, Bitbucket en Azure DevOps: alleen handmatig, vaste versie, gecontroleerde downloads
import yaml
g = yaml.safe_load((VB / "gitlab-ci.yml").read_text())["checkmijn"]
assert g["rules"] == [{"if": '$CI_PIPELINE_SOURCE == "web"'}], g["rules"]
b = yaml.safe_load((VB / "bitbucket-pipelines.yml").read_text())["pipelines"]
assert list(b) == ["custom"], list(b)
a = yaml.safe_load((VB / "azure-pipelines.yml").read_text())
assert a["trigger"] == "none" and a["pr"] == "none", (a["trigger"], a["pr"])
for naam in ("gitlab-ci.yml", "bitbucket-pipelines.yml", "azure-pipelines.yml"):
    t = (VB / naam).read_text()
    assert "schedule" not in code(t) and "cron" not in code(t), naam
    assert re.search(r'versie = "[0-9a-f]{40}"', t), naam
    assert len(re.findall(r'"[0-9a-f]{64}"', t)) == 3, naam
    assert "--require-hashes" in t and "CM_MEETELLEN=false" in t and "CM_RAPPORT_LINK=false" in t, naam
    v = re.search(r'versie = "([0-9a-f]{40})"', t).group(1)
    gh = re.search(r"AIScanner@([0-9a-f]{40})", code(regels("checkmijn.yml"))).group(1)
    assert v == gh, (naam, "andere vaste versie dan GitHub")
print("ok: workflowbestanden veilig")
