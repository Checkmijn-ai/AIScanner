"""Geheimen in code, configuratie en git-geschiedenis (E-05) en in mobiele apps (S-04)."""
from __future__ import annotations

from . import check
from ..core import Finding, Result, mask, snippet, redact
from ..secretscan import scan_text, scan_history, nice

MOBILE_HINT = ("android/", "ios/", "app/src/main", ".xcodeproj", "Info.plist", "AndroidManifest.xml", "google-services.json",
               "GoogleService-Info.plist", "app.json", "eas.json")


def _current(proj):
    if hasattr(proj, "_secrets"):
        return proj._secrets
    from ..secretscan import PUBLIEK
    PUBLIEK.clear()
    hits = []
    for p in proj.files:
        rel = proj.rel(p)
        if p.name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock") or rel.endswith(".min.js") \
                or p.suffix.lower() in (".svg", ".map"):
            continue
        for (ln, rid, desc, secret, line) in scan_text(proj.text(p), rel):
            hits.append((rel, ln, rid, desc, secret, line))
    proj._secrets = hits
    return hits


def _redact(line, secret):
    return redact(line, secret)


@check("E-05")
def secrets(proj, meta):
    r = Result("E-05")
    cur = _current(proj)
    from .agent import agent_files
    agent_rel = {proj.rel(p) for p in agent_files(proj)}
    seen = {secret for rel, ln, rid, desc, secret, line in cur if rel in agent_rel}
    for rel, ln, rid, desc, secret, line in cur:
        if any(h in rel for h in MOBILE_HINT):
            continue  # komt bij S-04
        if rel in agent_rel:
            continue  # komt bij B-05
        from .code import TEST_PATH
        sev = "Hoog" if TEST_PATH.search(rel) else "Kritiek"
        r.add(Finding("E-05", sev, f"Geheim in de code: {nice(rid)}", rel, ln, _redact(line, secret)))
        seen.add(secret)
    if agent_rel & {x[0] for x in cur}:
        r.info.append("Geheimen in agentconfiguratie staan bij B-05.")
    r.info.append(f"{len(proj.files)} bestanden doorzocht met {221} regels voor geheimen (gebaseerd op gitleaks).")
    from ..secretscan import PUBLIEK
    publiek = sorted({(pad, uitleg) for pad, ln, uitleg in PUBLIEK})
    for pad, uitleg in publiek[:5]:
        r.info.append(f"{pad}: {uitleg}. Die mag in de frontend staan, maar alleen als Row Level Security aan staat "
                      f"op elke tabel met gebruikersgegevens.")
    if proj.git:
        hist = scan_history(proj.root)
        if hist is None:
            r.info.append("De git-geschiedenis kon niet gelezen worden.")
        else:
            n = 0
            for commit, date, fname, rid, desc, secret, line in hist:
                if secret in seen:
                    continue
                seen.add(secret)
                n += 1
                r.add(Finding("E-05", "Kritiek", f"Geheim in de git-geschiedenis: {nice(rid)}", fname, 0,
                              f"commit {commit} ({date}): {_redact(line, secret)} — verwijderd uit de code is niet genoeg: "
                              "het geheim moet ingetrokken worden."))
            r.info.append("De volledige git-geschiedenis is mee doorzocht.")
    else:
        r.info.append("Geen git-repository: de geschiedenis kon niet doorzocht worden.")
    return r


@check("S-04")
def mobile_secrets(proj, meta):
    r = Result("S-04")
    if not proj.is_mobile():
        r.status, r.reden = "Niet van toepassing", "Geen mobiele app gevonden."
        return r
    for rel, ln, rid, desc, secret, line in _current(proj):
        if any(h in rel for h in MOBILE_HINT):
            r.add(Finding("S-04", meta["ernst"], f"Geheim in de mobiele app: {nice(rid)}", rel, ln, _redact(line, secret)))
    return r
