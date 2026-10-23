"""OTAP-route (R-14): gaat elke wijziging eerst langs test of acceptatie voor ze in productie komt?

Niet de vraag of er een testomgeving bestaat, maar of er volgens die route gewerkt wordt: niets rechtstreeks naar productie.
Wat de scan bekijkt:
- de pipeline: wordt er naar productie uitgerold, en is er ook een uitrol naar een test- of acceptatieomgeving;
- de geschiedenis van de productiebranch: hoeveel recente wijzigingen kwamen er rechtstreeks op, zonder pull request
  of samenvoeging vanuit een testbranch (wijzigingen door bouwtools zoals Lovable tellen als rechtstreeks);
- met een GitHub-token: of de productiebranch nu een pull request verplicht maakt.
"""
from __future__ import annotations

import re
import subprocess

from . import check
from ..core import Finding, Result
from .ci import ci_files

DEPLOY = re.compile(r"(vercel\b[^\n]*(deploy|--prod)|netlify deploy|fly(ctl)? deploy|firebase deploy|supabase (db push|functions deploy)|"
                    r"kubectl (apply|rollout)|helm (upgrade|install)|docker (push|compose[^\n]*up)|appleboy/ssh-action|"
                    r"\bssh\b[^\n]*(deploy|uitrol|docker)|\brsync\b|aws (s3 sync|ecs|deploy|lambda update)|gcloud (run|app) deploy|"
                    r"azure/webapps-deploy|railway up|heroku|wrangler(-action| deploy| publish)|\buitrol)", re.I)
TESTNAAM = r"(test|testing|staging|stage|acc|acceptatie|acceptance|uat|preview|develop|dev|ontwikkel)"
TEST_ROUTE = re.compile(r"(environment:\s*['\"]?(name:\s*)?" + TESTNAAM + r"\b|branches:\s*\[[^\]]*\b" + TESTNAAM + r"\b|"
                        r"branches:\s*\n(\s*-\s*\S+\n)*?\s*-\s*['\"]?" + TESTNAAM + r"\b|vercel deploy(?![^\n]*--prod))", re.I)
AUTOMATISCH = re.compile(r"(\[skip ci\]|checkmijn\.ai: scanrapport)", re.I)
BOTS = {"checkmijn.ai", "github-actions[bot]", "dependabot[bot]", "renovate[bot]"}
BOUWTOOL = re.compile(r"(gpt-engineer-app\[bot\]|lovable|bolt|v0\[bot\]|X-Lovable-Edit-ID)", re.I)
VIA_PR = re.compile(r"(\(#\d+\)\s*$|^Merge pull request #\d+|^Merge branch '" + TESTNAAM + r"'|^Merge remote-tracking branch "
                    r"'origin/" + TESTNAAM + r"')", re.I)
RECENT = 20


def _git(proj, *args):
    return subprocess.run(["git", "-C", str(proj.root), *args], capture_output=True, text=True, timeout=30).stdout


def _prodbranch(proj) -> str | None:
    for kandidaat in ("origin/HEAD", "origin/main", "origin/master", "main", "master"):
        if _git(proj, "rev-parse", "--verify", "--quiet", kandidaat).strip():
            return kandidaat
    return "HEAD"


def _geschiedenis(proj):
    """Recente wijzigingen op de productiebranch: lijst van (rechtstreeks: bool, door_bouwtool: bool, onderwerp)."""
    if not proj.git:
        return None, None
    b = _prodbranch(proj)
    ruw = _git(proj, "log", "--first-parent", "-n", "200", "--format=%x1e%an%x1f%cn%x1f%P%x1f%s%x1f%b", b)
    uit = []
    for blok in ruw.split("\x1e"):
        if not blok.strip():
            continue
        delen = blok.split("\x1f")
        if len(delen) < 5:
            continue
        auteur, committer, ouders, onderwerp, body = delen[0], delen[1], delen[2].split(), delen[3], delen[4]
        if auteur in BOTS or AUTOMATISCH.search(onderwerp):
            continue
        bouwtool = bool(BOUWTOOL.search(auteur) or BOUWTOOL.search(committer) or "X-Lovable-Edit-ID" in body)
        via = bool(VIA_PR.search(onderwerp)) or (len(ouders) > 1 and not bouwtool)
        uit.append((not via, bouwtool, onderwerp))
        if len(uit) >= RECENT:
            break
    return uit, ("de productiebranch" if b == "HEAD" else b.replace("origin/", ""))


def _pr_verplicht(proj):
    """True/False als het token het kan zien, anders None."""
    if proj.offline or not proj.github_token or not proj.git:
        return None
    from .github import _api, _remote
    rem = _remote(proj)
    if not rem or rem[0] == "other":
        return None
    try:
        o, n = rem
        code, repo = _api(proj, f"/repos/{o}/{n}")
        if code != 200:
            return None
        b = repo.get("default_branch", "main")
        code, rules = _api(proj, f"/repos/{o}/{n}/rules/branches/{b}")
        types = {x.get("type") for x in (rules or [])} if code == 200 and isinstance(rules, list) else set()
        code2, prot = _api(proj, f"/repos/{o}/{n}/branches/{b}/protection")
        return "pull_request" in types or bool(code2 == 200 and (prot or {}).get("required_pull_request_reviews"))
    except Exception:  # noqa: BLE001
        return None


@check("R-14")
def otap_route(proj, meta):
    r = Result("R-14")
    teksten = {proj.rel(p): proj.text(p) for p in ci_files(proj)}
    uitrol = [f for f, t in teksten.items() if DEPLOY.search(t)]
    testroute = [f for f in uitrol if TEST_ROUTE.search(teksten[f])]
    hist, branch = _geschiedenis(proj)
    pr = _pr_verplicht(proj)

    if not uitrol and not hist:
        r.status, r.reden = "Niet gescand", "Geen pipeline met een uitrol en geen git-geschiedenis om de route na te gaan."
        return r
    if uitrol:
        r.info.append("Uitrol in de pipeline: " + ", ".join(uitrol) + ".")
    r.info.append("Uitrol naar een test- of acceptatieomgeving: " + (", ".join(testroute) if testroute else "niet gevonden") + ".")
    if pr is not None:
        r.info.append(f"De productiebranch {'vraagt' if pr else 'vraagt geen'} pull request (uitgelezen via GitHub).")

    rechtstreeks = [x for x in (hist or []) if x[0]]
    bouwtool = sum(1 for x in rechtstreeks if x[1])
    if hist:
        r.info.append(f"Van de laatste {len(hist)} wijzigingen op {branch} kwamen er {len(rechtstreeks)} rechtstreeks op, zonder "
                      "pull request of samenvoeging vanuit een testbranch" + (f" ({bouwtool} door een bouwtool zoals Lovable)" if bouwtool else "") + ".")
    if hist and len(hist) < 5:
        r.info.append("Weinig geschiedenis beschikbaar (bv. een checkout met fetch-depth 1): de telling zegt weinig.")

    plaats = branch or (uitrol[0] if uitrol else "")
    veel = bool(hist) and len(hist) >= 5 and len(rechtstreeks) >= 3 and len(rechtstreeks) / len(hist) >= 0.5
    if pr is True and testroute:
        return r  # route afgedwongen: pull request verplicht en een aparte testomgeving
    if veel and not testroute and pr is not True:
        r.add(Finding("R-14", "Hoog", "Wijzigingen gaan rechtstreeks naar productie, zonder test- of acceptatiestap", plaats, 0,
                      f"{len(rechtstreeks)} van de laatste {len(hist)} wijzigingen kwamen rechtstreeks op de productiebranch, en de "
                      "pipeline rolt nergens uit naar een test- of acceptatieomgeving. Werk met een testbranch die eerst naar een "
                      "testomgeving gaat, en zet de productiebranch op slot (alleen via pull request)."))
    elif rechtstreeks and pr is not True:
        r.add(Finding("R-14", "Middel", "De OTAP-route wordt soms overgeslagen", plaats, 0,
                      f"{len(rechtstreeks)} van de laatste {len(hist)} wijzigingen kwamen rechtstreeks op de productiebranch. "
                      "Zet de productiebranch op slot, zodat alles eerst via test gaat.", bevestigen=pr is None))
    elif not testroute:
        r.add(Finding("R-14", "Middel", "Geen uitrol naar een test- of acceptatieomgeving gevonden", plaats, 0,
                      "Elke wijziging zou eerst op een test- of acceptatieomgeving moeten staan voor ze naar productie gaat.",
                      bevestigen=True))
    return r
