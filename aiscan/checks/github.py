"""Branchbeveiliging (R-03) en repository-instellingen (R-13), uitgelezen via de API van GitHub."""
from __future__ import annotations

import re
import subprocess

from . import check
from ..core import Finding, Result


def _remote(proj):
    if not proj.git:
        return None
    try:
        url = subprocess.run(["git", "-C", str(proj.root), "remote", "get-url", "origin"], capture_output=True,
                             text=True, timeout=10).stdout.strip()
    except Exception:
        return None
    m = re.search(r"github\.com[:/]([^/]+)/([^/.]+?)(?:\.git)?$", url)
    return (m.group(1), m.group(2)) if m else ("other", url) if url else None


def _api(proj, path):
    import requests
    h = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {proj.github_token}",
         "X-GitHub-Api-Version": "2022-11-28"}
    resp = requests.get("https://api.github.com" + path, headers=h, timeout=15)
    return resp.status_code, (resp.json() if resp.content and resp.headers.get("content-type", "").startswith("application/json") else None)


def _precheck(proj, cid):
    r = Result(cid)
    rem = _remote(proj)
    if rem is None:
        r.status, r.reden = "Niet gescand", "Geen git-repository met een remote gevonden."
    elif rem[0] == "other":
        r.status, r.reden = "Niet gescand", "De repository staat niet op GitHub; GitLab en andere platforms volgen in een latere versie."
    elif not proj.github_token:
        r.status, r.reden = "Niet gescand", "Geen GitHub-token opgegeven (--github-token met leesrechten op de repository)."
    elif proj.offline:
        r.status, r.reden = "Niet gescand", "Offline gestart; de API van GitHub is niet geraadpleegd."
    return r, rem


@check("R-03")
def branch_protection(proj, meta):
    r, rem = _precheck(proj, "R-03")
    if r.status != "Geen bevinding":
        return r
    o, n = rem
    try:
        code, repo = _api(proj, f"/repos/{o}/{n}")
        if code != 200:
            r.status, r.reden = "Niet gescand", f"Repository niet leesbaar met dit token (HTTP {code})."
            return r
        b = repo.get("default_branch", "main")
        code, rules = _api(proj, f"/repos/{o}/{n}/rules/branches/{b}")
        types = {x.get("type") for x in (rules or [])} if code == 200 and isinstance(rules, list) else set()
        code2, prot = _api(proj, f"/repos/{o}/{n}/branches/{b}/protection")
        prot = prot if code2 == 200 else {}
        review = "pull_request" in types or bool(prot.get("required_pull_request_reviews"))
        nforce = "non_fast_forward" in types or (prot and not (prot.get("allow_force_pushes") or {}).get("enabled"))
        status = "required_status_checks" in types or bool(prot.get("required_status_checks"))
        if not (types or prot):
            r.add(Finding("R-03", meta["ernst"], f"De hoofdbranch '{b}' is niet beveiligd", f"github.com/{o}/{n}"))
            return r
        if not review:
            r.add(Finding("R-03", meta["ernst"], "Geen verplichte review via pull request op de hoofdbranch", f"github.com/{o}/{n}"))
        if not nforce:
            r.add(Finding("R-03", meta["ernst"], "Geforceerd pushen naar de hoofdbranch is toegestaan", f"github.com/{o}/{n}"))
        if not status:
            r.add(Finding("R-03", "Middel", "Een geslaagde pipeline is niet verplicht voor een merge", f"github.com/{o}/{n}"))
        r.info.append(f"Branch '{b}' uitgelezen via de API van GitHub.")
    except Exception as e:  # netwerk
        r.status, r.reden = "Niet gescand", f"API van GitHub niet bereikbaar ({type(e).__name__})."
    return r


@check("R-13")
def repo_settings(proj, meta):
    r, rem = _precheck(proj, "R-13")
    if r.status != "Geen bevinding":
        return r
    o, n = rem
    try:
        code, repo = _api(proj, f"/repos/{o}/{n}")
        if code != 200:
            r.status, r.reden = "Niet gescand", f"Repository niet leesbaar met dit token (HTTP {code})."
            return r
        sa = repo.get("security_and_analysis") or {}
        if not sa:
            # Dit token mag de beveiligingsinstellingen niet zien (bv. het standaardtoken van GitHub Actions): onbekend, geen bevinding.
            r.info.append("Of geheimenscanning en push protection aanstaan, kon dit token niet zien. Kijk het na bij "
                          "Settings → Advanced Security.")
        else:
            if (sa.get("secret_scanning") or {}).get("status") != "enabled":
                r.add(Finding("R-13", meta["ernst"], "Geheimenscanning staat niet aan", f"github.com/{o}/{n}"))
            if (sa.get("secret_scanning_push_protection") or {}).get("status") != "enabled":
                r.add(Finding("R-13", "Laag", "Push protection voor geheimen staat niet aan", f"github.com/{o}/{n}"))
        code, _ = _api(proj, f"/repos/{o}/{n}/vulnerability-alerts")
        if code == 404:
            r.add(Finding("R-13", meta["ernst"], "Waarschuwingen voor kwetsbare afhankelijkheden staan niet aan", f"github.com/{o}/{n}"))
        if repo.get("visibility") == "public":
            r.add(Finding("R-13", "Info", "De repository is publiek", f"github.com/{o}/{n}", bevestigen=True,
                          bewijs="Is dat de bedoeling? Een publieke repository is soms onbedoeld."))
        r.info.append("Langlevende persoonlijke tokens zijn niet via de API te zien; de bouwer bevestigt dit.")
    except Exception as e:
        r.status, r.reden = "Niet gescand", f"API van GitHub niet bereikbaar ({type(e).__name__})."
    return r
