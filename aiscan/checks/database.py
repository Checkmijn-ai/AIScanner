"""Rechten per rij in de databank (W-13): Row Level Security bij Supabase/Postgres en Security Rules bij Firebase.

Statisch, op de migraties en regelbestanden in de repository (de klant draait de scan zelf, er gaat niets naar buiten):
- een tabel in het schema public zonder Row Level Security: iedereen met de publieke sleutel kan ze lezen en wijzigen;
- een policy die iedereen laat schrijven (USING/WITH CHECK (true) voor anon of public);
- tabellen die iedereen mag lezen: één melding om na te kijken (vaak bedoeld, bv. producten);
- Firebase-regels die alles toelaten (allow read, write: if true).
De echte test met twee accounts hoort bij de keuring.
"""
from __future__ import annotations

import re

from . import check
from ..core import Finding, Result, snippet

NAAM = r'(?:"?(\w+)"?\.)?"?(\w+)"?'
CREATE = re.compile(r"\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?" + NAAM, re.I)
DROP = re.compile(r"\bdrop\s+table\s+(?:if\s+exists\s+)?" + NAAM, re.I)
RLS = re.compile(r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?" + NAAM + r"\s+(enable|disable)\s+row\s+level\s+security", re.I)
POLICY = re.compile(r"\bcreate\s+policy\s+(\"[^\"]*\"|\w+)\s+on\s+" + NAAM + r"(.*)", re.I | re.S)
DROP_POLICY = re.compile(r"\bdrop\s+policy\s+(?:if\s+exists\s+)?(\"[^\"]*\"|\w+)\s+on\s+" + NAAM, re.I)
SCHEMA_OK = {None, "public"}
ALLES_TOE = re.compile(r"\(\s*true\s*\)")


def _zonder_commentaar(sql: str) -> str:
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    return re.sub(r"--[^\n]*", " ", sql)


def _statements(sql: str):
    """Grof in statements knippen op ';' buiten $$-blokken (functies)."""
    out, buf, in_dollar = [], [], False
    for deel in re.split(r"(\$\w*\$|;)", sql):
        if re.fullmatch(r"\$\w*\$", deel or ""):
            in_dollar = not in_dollar
            buf.append(deel)
        elif deel == ";" and not in_dollar:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(deel)
    if "".join(buf).strip():
        out.append("".join(buf))
    return out


def _regel(tekst: str, pos: int) -> int:
    return tekst.count("\n", 0, pos) + 1


def _supabase(proj, r: Result):
    migraties = sorted(proj.find("supabase/migrations/*.sql", "*/supabase/migrations/*.sql", "supabase/schema.sql",
                                 "db/migrations/*.sql", "migrations/*.sql", where="all_files"), key=lambda p: p.name)
    if not migraties:
        return False
    tabellen = {}   # naam -> (bestand, regel)
    rls = {}        # naam -> bool
    policies = {}   # (tabel, naam) -> (cmd, iedereen, open, bestand, regel, bewijs)
    for p in migraties:
        ruw = proj.text(p)
        sql = _zonder_commentaar(ruw)
        rel = proj.rel(p)
        for st in _statements(sql):
            for m in CREATE.finditer(st):
                if m.group(1) in SCHEMA_OK or (m.group(1) or "").lower() == "public":
                    regel = _regel(ruw, ruw.find(m.group(0))) if m.group(0) in ruw else 0
                    tabellen[m.group(2).lower()] = (rel, regel)
            for m in DROP.finditer(st):
                tabellen.pop(m.group(2).lower(), None)
                policies = {k: v for k, v in policies.items() if k[0] != m.group(2).lower()}
            for m in DROP_POLICY.finditer(st):
                policies.pop((m.group(3).lower(), m.group(1).strip('"').lower()), None)
            for m in RLS.finditer(st):
                rls[m.group(2).lower()] = m.group(3).lower() == "enable"
            m = POLICY.search(st)
            if m and ((m.group(2) or "public").lower() == "public"):
                pnaam, tabel, rest = m.group(1).strip('"').lower(), m.group(3).lower(), m.group(4)
                cmd = (re.search(r"\bfor\s+(all|select|insert|update|delete)\b", rest, re.I) or [None, "all"])[1].lower()
                rollen = re.search(r"\bto\s+([\w\s,\"]+?)(?=\busing\b|\bwith\b|$)", rest, re.I | re.S)
                rollen = {x.strip(' "').lower() for x in rollen.group(1).split(",")} if rollen else {"public"}
                open_ = ALLES_TOE.search((re.search(r"\busing\s*(\(.*)", rest, re.I | re.S) or [None, ""])[1][:12]) or \
                    ALLES_TOE.search((re.search(r"\bwith\s+check\s*(\(.*)", rest, re.I | re.S) or [None, ""])[1][:12])
                kop = re.search(r"create\s+policy\s+" + re.escape(m.group(1)), ruw, re.I)
                policies[(tabel, pnaam)] = (cmd, bool(rollen & {"public", "anon"}), bool(open_), rel,
                                            _regel(ruw, kop.start()) if kop else 0, snippet(" ".join(st.split())))
    schrijven = [(t, cmd, ied, rel, regel, bew) for (t, _), (cmd, ied, open_, rel, regel, bew) in policies.items()
                 if open_ and cmd in ("insert", "update", "delete", "all") and t in tabellen]
    lezen = [t for (t, _), (cmd, ied, open_, *_x) in policies.items() if open_ and ied and cmd == "select" and t in tabellen]
    for naam, (rel, regel) in sorted(tabellen.items()):
        if not rls.get(naam):
            r.add(Finding("W-13", "Hoog", f"Tabel '{naam}' zonder Row Level Security", rel, regel,
                          "Zonder RLS kan iedereen met de publieke sleutel van de app deze tabel lezen en wijzigen. "
                          f"Zet aan: ALTER TABLE public.{naam} ENABLE ROW LEVEL SECURITY; en voeg policies toe."))
    for tabel, cmd, iedereen, rel, regel, bewijs in schrijven:
        wie = "iedereen, ook zonder inloggen," if iedereen else "elke ingelogde gebruiker"
        r.add(Finding("W-13", "Hoog" if iedereen else "Middel",
                      f"Policy op '{tabel}' laat {wie} {'schrijven' if cmd != 'all' else 'alles doen'} ({cmd.upper()} met true)",
                      rel, regel, bewijs, bevestigen=True))
    if lezen:
        uniek = sorted(set(lezen))
        r.add(Finding("W-13", "Laag", f"{len(uniek)} tabel(len) die iedereen mag lezen (SELECT met true)",
                      proj.rel(migraties[-1]), 0, "Kijk na of dat de bedoeling is: " + ", ".join(uniek[:12])
                      + (" …" if len(uniek) > 12 else ""), bevestigen=True))
    r.info.append(f"{len(migraties)} migratie(s) gelezen: {len(tabellen)} tabel(len) in public, "
                  f"{sum(1 for t in tabellen if rls.get(t))} met Row Level Security.")
    return True


FB_OPEN = re.compile(r"allow\s+(?:read|write|create|update|delete|get|list)(?:\s*,\s*\w+)*\s*(?::\s*if\s+true\s*)?;", re.I)


def _firebase(proj, r: Result):
    regels = proj.find("firestore.rules", "storage.rules", "*.rules", where="all_files")
    rtdb = proj.find("database.rules.json", where="all_files")
    if not regels and not rtdb:
        return False
    for p in regels:
        for i, line in enumerate(proj.text(p).splitlines(), 1):
            s = line.strip()
            if FB_OPEN.search(s) and (re.search(r"if\s+true\s*;", s) or not re.search(r"\bif\b", s)):
                r.add(Finding("W-13", "Kritiek", "Firebase-regel laat iedereen toe", proj.rel(p), i, snippet(s)))
    for p in rtdb:
        t = proj.text(p)
        for m in re.finditer(r"\"\.(read|write)\"\s*:\s*(true|\"true\")", t):
            r.add(Finding("W-13", "Kritiek", f"Realtime Database: .{m.group(1)} staat open voor iedereen", proj.rel(p),
                          _regel(t, m.start()), snippet(m.group(0))))
    r.info.append(f"Firebase-regels gelezen: {', '.join(proj.rel(p) for p in regels + rtdb)}.")
    return True


@check("W-13")
def rechten_per_rij(proj, meta):
    r = Result("W-13")
    sb, fb = _supabase(proj, r), _firebase(proj, r)
    if sb or fb:
        r.status = "Bevinding" if r.findings else "Geen bevinding"
        r.info.append("De test met twee accounts (kan gebruiker A de gegevens van B zien?) hoort bij de keuring.")
        return r
    gebruikt = any(re.search(r"@supabase/supabase-js|\bsupabase\b|firebase", proj.text(p))
                   for p in proj.find("package.json", "requirements*.txt", "pyproject.toml", where="all_files"))
    if gebruikt:
        r.status, r.reden = "Niet gescand", ("De app gebruikt Supabase of Firebase, maar de migraties of regels staan niet in de "
                                             "repository. Zet ze erin (supabase/migrations, firestore.rules) zodat ze nagekeken kunnen worden.")
    else:
        r.status, r.reden = "Niet van toepassing", "Geen Supabase of Firebase gevonden."
    return r
