"""Achtergebleven rommel in repository en artefact (C-20)."""
from __future__ import annotations

import fnmatch
import re

from . import check
from ..core import Finding, Result

RULES = [
    # (patroon, ernst, titel)  — .env-bestanden en .sql worden apart beoordeeld (zie leftovers)
    (("*.dump", "*.sqlite", "*.sqlite3", "*.db", "*.bak.sql", "*.mdb", "*dump*.sql", "*backup*.sql", "*.sql.gz"), "Hoog",
     "Databasebestand of dump in de repository"),
    (("*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_ed25519", "*.keystore", "*.jks"), "Kritiek", "Sleutelbestand in de repository"),
    (("*.bak", "*.old", "*.orig", "*.rej", "*.swp", "*.swo", "*~", "*.tmp", "*.temp"), "Laag", "Back-up- of tijdelijk bestand"),
    ((".aider.chat.history.md", ".aider.input.history", ".aider.tags.cache*", "*.aider*", ".claude/settings.local.json",
      "claude-*.log", ".cursor/*history*", ".specstory/*", "*.agent.log"), "Middel", "Tijdelijk bestand of geschiedenis van een AI-agent"),
    (("*.log", "npm-debug.log*", "yarn-error.log"), "Laag", "Logbestand in de repository"),
    ((".DS_Store", "Thumbs.db", "desktop.ini"), "Laag", "Systeembestand in de repository"),
    (("*.pyc", "__pycache__/*"), "Laag", "Gecompileerde Python-bestanden in de repository"),
]
BUILD_DIRS = ("node_modules/", "dist/", "build/", ".next/", "out/", "target/", "coverage/", "vendor/bundle/")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@(?!example\.|test\.|localhost)[A-Za-z0-9-]+\.[A-Za-z0-9.-]+\b")


PUBLIEK = re.compile(r"^(VITE_|NEXT_PUBLIC_|PUBLIC_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|GATSBY_)|"
                     r"(_URL|_PROJECT_ID|_PUBLISHABLE_KEY|_ANON_KEY|_PROJECT_REF)$")


def _env_sleutels(proj, rel):
    out = []
    for line in proj.text(proj.root / rel).splitlines():
        m = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if m:
            out.append(m.group(1))
    return out


def _env_ernst(proj, rel):
    keys = _env_sleutels(proj, rel)
    if keys and all(PUBLIEK.search(k) for k in keys):
        return "Laag", "Omgevingsbestand in de repository, met alleen publieke waarden"
    return "Hoog", "Omgevingsbestand met configuratie in de repository"


def _env_bewijs(proj, rel):
    keys = _env_sleutels(proj, rel)
    geheim = [k for k in keys if not PUBLIEK.search(k)]
    if not keys:
        return ""
    if not geheim:
        return (f"{len(keys)} variabele(n), allemaal publiek bedoeld (zoals {keys[0]}). Zet .env toch in .gitignore, "
                "zodat er later geen geheim mee in git komt.")
    return f"Variabelen die geheim kunnen zijn: {', '.join(geheim[:5])}."


def _alleen_publiek(proj, rel) -> bool:
    """Een PEM-bestand met alleen publieke sleutels of certificaten (geen PRIVATE KEY) hoort gewoon in de repository."""
    t = proj.text(proj.root / rel)
    blokken = re.findall(r"-----BEGIN ([A-Z0-9 ]+)-----", t)
    return bool(blokken) and all(b in ("PUBLIC KEY", "CERTIFICATE", "RSA PUBLIC KEY", "X509 CRL") for b in blokken) \
        and "PRIVATE" not in t


@check("C-20")
def leftovers(proj, meta):
    r = Result("C-20")
    if proj.tracked is not None:
        pool = sorted(proj.tracked)
        r.info.append(f"{len(pool)} bestanden onder versiebeheer bekeken.")
    else:
        pool = sorted(proj.rel(p) for p in proj.all_files)
        r.info.append("Geen git-repository: alle bestanden in de map bekeken.")
    seen_dirs = set()
    for rel in pool:
        name = rel.rsplit("/", 1)[-1]
        if name in (".env.example", ".env.sample", ".env.template", ".env.dist", ".env.test.example"):
            continue
        if name.endswith(".sql"):
            # migraties en schema's horen in de repository; een los SQL-bestand met veel rijen is verdacht
            low = rel.lower()
            inhoud = proj.text(proj.root / rel)
            dumpnaam = re.search(r"(dump|backup|bak|export|prod)", name.lower())
            dumpkop = re.search(r"(?i)(mysql dump|pg_dump|postgresql database dump|sqlite dump)", inhoud[:2000])
            if dumpnaam or dumpkop:
                r.add(Finding("C-20", "Hoog", "Databasebestand of dump in de repository", rel))
            elif re.search(r"(^|/)(migrations?|migrate|schema|supabase|drizzle|prisma|db/migrate|flyway|liquibase)(/|$)", low):
                pass  # migraties en schema's horen in de repository
            elif len(re.findall(r"(?im)^\s*insert\s+into\b", inhoud)) >= 20:
                r.add(Finding("C-20", "Hoog", "SQL-bestand met veel gegevensrijen: mogelijk een dump", rel, bevestigen=True))
            continue
        if name.startswith(".env") and name not in (".env.example",):
            sev, title = _env_ernst(proj, rel)
            r.add(Finding("C-20", sev, title, rel, bewijs=_env_bewijs(proj, rel)))
            continue
        if name.endswith((".pem", ".key", ".crt", ".pub")) and _alleen_publiek(proj, rel):
            r.info.append(f"{rel}: alleen een publieke sleutel of certificaat, geen geheim.")
            continue
        for pats, sev, title in RULES:
            if any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(rel, p) for p in pats):
                if "test" in rel.lower() and sev in ("Hoog",) and name.endswith((".db", ".sqlite", ".sqlite3")):
                    sev = "Middel"
                r.add(Finding("C-20", sev, title, rel))
                break
        if proj.tracked is not None:
            for d in BUILD_DIRS:
                if rel.startswith(d) or f"/{d}" in rel:
                    top = rel.split(d)[0] + d
                    if top not in seen_dirs:
                        seen_dirs.add(top)
                        r.add(Finding("C-20", "Middel" if d == "node_modules/" else "Laag",
                                      f"Gebouwde uitvoer of geïnstalleerde pakketten in de repository ({d.rstrip('/')})", top))
    # testgegevens die op echte persoonsgegevens lijken
    for p in proj.files:
        rel = proj.rel(p)
        if p.suffix.lower() in (".csv", ".json", ".sql", ".xlsx") and re.search(r"(?i)(fixture|seed|test|sample|mock|data)", rel):
            mails = {m.group(0).lower() for m in EMAIL.finditer(proj.text(p))}
            real = {m for m in mails if not re.search(r"(example|test|fake|dummy|acme|foo|bar)", m)}
            if len(real) >= 5:
                r.add(Finding("C-20", "Hoog", f"Testgegevens met mogelijk echte persoonsgegevens ({len(real)} e-mailadressen)",
                              rel, bevestigen=True))
    return r
