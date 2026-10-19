"""Supply chain: SBOM (A-03), build (C-07), lockfiles (F-03), lekken (F-01, F-13), verouderd (F-02),
licenties (F-05), verzonnen of verdachte pakketten (B-06), ongebruikte pakketten (C-19)."""
from __future__ import annotations

import datetime as dt
import gzip
import json
import re
from functools import lru_cache
from pathlib import Path

import yaml

from . import check
from ..core import Finding, Result, snippet
from ..deps import all_manifests, all_components, norm_py, min_version
from ..versions import affected, fixed_in, key as vkey

DATA = Path(__file__).resolve().parent.parent / "data"
SEV = {"CRITICAL": "Kritiek", "HIGH": "Hoog", "MODERATE": "Middel", "LOW": "Laag"}


@lru_cache(maxsize=1)
def ref():
    return yaml.safe_load((DATA / "reference.yaml").read_text())


@lru_cache(maxsize=1)
def advisories():
    with gzip.open(DATA / "advisories.json.gz", "rt") as f:
        return json.load(f)


def _ci_text(proj):
    files = proj.find(".github/workflows/*.yml", ".github/workflows/*.yaml", ".gitlab-ci.yml",
                      "azure-pipelines.yml", "bitbucket-pipelines.yml", "Jenkinsfile", ".circleci/config.yml")
    return files, "\n".join(proj.text(p) for p in files)


# ------------------------------------------------------------------ A-03
@check("A-03")
def sbom(proj, meta):
    r = Result("A-03")
    comps = all_components(proj)
    if not all_manifests(proj):
        r.status, r.reden = "Niet van toepassing", "Geen npm- of Python-manifest gevonden."
        return r
    existing = proj.find("*.cdx.json", "bom.json", "sbom*.json", "*.spdx.json", "*.spdx", "bom.xml")
    _, ci = _ci_text(proj)
    in_ci = re.search(r"\b(syft|cyclonedx|cdxgen|spdx-sbom-generator|sbom-tool|anchore/sbom-action)\b", ci, re.I)
    r.info.append(f"De scanner maakte zelf een SBOM (CycloneDX 1.5) met {len(comps)} componenten: sbom.json.")
    if in_ci:
        r.info.append(f"De pipeline maakt een SBOM ({in_ci.group(1)}).")
    elif existing:
        r.add(Finding("A-03", "Laag", "Er staat een SBOM in de repository, maar de pipeline maakt ze niet automatisch bij elke build",
                      proj.rel(existing[0])))
    else:
        r.add(Finding("A-03", meta["ernst"], "Geen SBOM die automatisch bij de build gemaakt wordt",
                      bewijs="Geen SBOM-bestand in de repository en geen SBOM-stap (syft, cyclonedx, cdxgen) in de pipeline."))
    return r


def write_sbom(proj, path: Path, app_name: str):
    comps = all_components(proj)
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"timestamp": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                     "tools": [{"name": "aiscan", "version": "0.1"}],
                     "component": {"type": "application", "name": app_name}},
        "components": [
            {"type": "library", "name": c.name, "version": c.version or "", "purl": c.purl,
             **({"licenses": [{"license": {"id": c.license}}]} if c.license else {}),
             "scope": "optional" if c.dev else "required",
             "properties": [{"name": "aiscan:direct", "value": str(c.direct).lower()},
                            {"name": "aiscan:bron", "value": c.source}]}
            for c in comps],
    }
    path.write_text(json.dumps(doc, indent=1))
    return len(comps)


# ------------------------------------------------------------------ C-07 en F-03
@check("C-07")
def build(proj, meta):
    r = Result("C-07")
    ms = all_manifests(proj)
    if not ms:
        r.status, r.reden = "Niet van toepassing", "Geen npm- of Python-manifest gevonden."
        return r
    for m in ms:
        if not m.lockfile:
            r.add(Finding("C-07", meta["ernst"], "Geen lockfile: versies liggen niet vast", proj.rel(m.path),
                          bewijs=f"{len(m.direct) + len(m.dev)} afhankelijkheden met een versiebereik, zonder lockfile."))
    readmes = proj.find("README*", "readme*", "CONTRIBUTING*", "docs/*.md")
    for m in ms:
        for lp, missing in getattr(m, "other_lockfiles", []):
            if missing:
                r.add(Finding("C-07", "Middel", f"Meerdere lockfiles die niet overeenkomen: {proj.rel(m.lockfile)} en {proj.rel(lp)}",
                              proj.rel(lp), bewijs=f"{len(missing)} pakket(ten) uit package.json ontbreken in {lp.name}, bv. "
                              f"{', '.join(missing[:3])}. Houd één lockfile en verwijder de andere."))
    instr = re.compile(r"\b(npm (ci|i|install|run build)\b|yarn( install| build)?|pnpm (i|install)|bun (i|install)\b|pip install|poetry install|"
                       r"uv sync|pipenv install|docker[- ]compose up|make (build|install)|mvn |gradle )", re.I)
    if not any(instr.search(proj.text(p)) for p in readmes):
        r.add(Finding("C-07", "Laag", "Geen gedocumenteerde opdracht om het project te bouwen",
                      bewijs="Geen README of handleiding met een installatie- of buildopdracht gevonden."))
    r.info.append(f"{len(ms)} manifest(en) bekeken.")
    return r


@check("F-03")
def lockfiles(proj, meta):
    r = Result("F-03")
    ms = all_manifests(proj)
    if not ms:
        r.status, r.reden = "Niet van toepassing", "Geen npm- of Python-manifest gevonden."
        return r
    for m in ms:
        if not m.lockfile:
            r.add(Finding("F-03", meta["ernst"], "Versies niet vastgezet met een lockfile", proj.rel(m.path)))
        elif not m.lock_has_integrity:
            sev = "Laag" if m.ecosystem == "PyPI" else meta["ernst"]
            zonder = sorted({c.name for c in m.components if not c.integrity})
            voorbeeld = f" Zonder hash: {', '.join(zonder[:5])}{' …' if len(zonder) > 5 else ''}." if zonder and len(zonder) < len(m.components) else ""
            r.add(Finding("F-03", sev, "Lockfile zonder integriteitscontrole (hashes)", proj.rel(m.lockfile),
                          bewijs="Niet elke afhankelijkheid heeft een hash; een gewijzigd pakket valt dan niet op." + voorbeeld))
    return r


# ------------------------------------------------------------------ F-01 en F-13
def _vulns(proj):
    if hasattr(proj, "_vulns"):
        return proj._vulns
    idx = advisories()["idx"]
    out, unchecked = [], 0
    for c in all_components(proj):
        ver = c.version or min_version(c.spec)
        if not ver:
            unchecked += 1
            continue
        name = c.name if c.ecosystem == "npm" else norm_py(c.name)
        for rec in idx.get(c.ecosystem, {}).get(name, []):
            if affected(c.ecosystem, ver, rec):
                out.append((c, rec))
    proj._vulns = (out, unchecked)
    return proj._vulns


@check("F-01")
def known_vulns(proj, meta):
    r = Result("F-01")
    comps = all_components(proj)
    if not comps:
        r.status, r.reden = "Niet van toepassing", "Geen afhankelijkheden gevonden."
        return r
    vulns, unchecked = _vulns(proj)
    m = advisories()["meta"]
    r.info.append(f"{len(comps)} componenten vergeleken met {m['bron']} (stand {m.get('stand')}).")
    if unchecked:
        r.info.append(f"{unchecked} componenten zonder vaste versie konden niet vergeleken worden.")
    if unchecked == len(comps):
        r.status, r.reden = "Niet gescand", "Geen vaste of afleidbare versies (geen lockfile); draai de scan na 'npm ci' of met een lockfile."
        return r
    ranged = sum(1 for c in comps if not c.version and min_version(c.spec))
    if ranged:
        r.info.append(f"{ranged} componenten zonder lockfile: vergeleken op de laagste versie die het versiebereik toelaat.")
    groups = {}
    for c, rec in vulns:
        if rec.get("mal"):
            continue  # komt bij B-06
        exact = c.version is None and bool(re.fullmatch(r"=?\s*\d+\.\d+\.\d+", (c.spec or "").strip()))
        groups.setdefault((c.name, c.version or min_version(c.spec), c.direct, c.dev, c.source, c.version is None and not exact), []).append(rec)
    for (name, ver, direct, dev, src, ranged_c), recs in groups.items():
        recs.sort(key=lambda x: -["LOW", "MODERATE", "HIGH", "CRITICAL"].index(x.get("sev", "MODERATE").upper())
                  if x.get("sev", "").upper() in ("LOW", "MODERATE", "HIGH", "CRITICAL") else 0)
        sev = SEV.get(recs[0].get("sev", "").upper(), "Middel")
        if dev:  # ontwikkelafhankelijkheid: komt niet in productie, telt één niveau lager
            sev = {"Kritiek": "Hoog", "Hoog": "Middel", "Middel": "Laag"}.get(sev, sev)
        eco = "npm" if src.endswith((".json", ".lock", ".yaml")) and "Pipfile" not in src else "PyPI"
        fixes = [f for rec in recs for f in fixed_in(eco, rec)]
        best = None
        for f in fixes:
            if best is None or (vkey(eco, f) or (0,)) > (vkey(eco, best) or (0,)):
                best = f
        cnt = {}
        for rec in recs:
            k = SEV.get(rec.get("sev", "").upper(), "Middel")
            cnt[k] = cnt.get(k, 0) + 1
        telling = ", ".join(f"{n} {k.lower()}" for k, n in sorted(cnt.items(), key=lambda kv: -["Laag", "Middel", "Hoog", "Kritiek"].index(kv[0])))
        ids = "; ".join(f"{rec['id']}{' (' + rec['cve'][0] + ')' if rec.get('cve') else ''}: {rec.get('sum', '')[:80]}" for rec in recs[:4])
        more = f"; en nog {len(recs) - 4}" if len(recs) > 4 else ""
        r.add(Finding("F-01", sev, f"{name} {('vanaf ' + ver) if ranged_c else ver}: {len(recs)} bekende kwetsbaarhe{'id' if len(recs) == 1 else 'den'} ({telling})"
                      f"{' · ontwikkelafhankelijkheid (telt één niveau lager)' if dev else ''}{' · indirect' if not direct else ''}", src, bevestigen=ranged_c,
                      bewijs=f"{ids}{more}" + (f" · bijwerken naar minstens {best}" if best else " · nog geen oplossing")))
    return r


@check("F-13")
def transitive(proj, meta):
    r = Result("F-13")
    ms = all_manifests(proj)
    if not ms:
        r.status, r.reden = "Niet van toepassing", "Geen afhankelijkheden gevonden."
        return r
    for m in ms:
        if not m.lockfile and m.ecosystem == "npm":
            r.add(Finding("F-13", meta["ernst"], "Indirecte afhankelijkheden kunnen niet gescand worden: geen lockfile",
                          proj.rel(m.path)))
    vulns, _ = _vulns(proj)
    ind = [v for v in vulns if not v[0].direct and not v[1].get("mal")]
    total_ind = sum(1 for c in all_components(proj) if not c.direct)
    r.info.append(f"{total_ind} indirecte componenten mee gescand; {len(ind)} bekende kwetsbaarheden daarin (zie F-01).")
    return r


# ------------------------------------------------------------------ F-02
def _eol_check(r, kind, version, where, line=0):
    table = ref()["eol"].get(kind, {})
    today = dt.date.today()
    v = version
    if kind in ("node", "vue", "jquery"):
        v = version.split(".")[0]
    elif kind in ("python", "django"):
        v = ".".join(version.split(".")[:2])
    end = table.get(v)
    if not end:
        return
    d = dt.date.fromisoformat(end)
    if d < today:
        r.add(Finding("F-02", "Hoog", f"{kind} {version} wordt niet meer ondersteund (sinds {end})", where, line))
    elif (d - today).days < 183:
        r.add(Finding("F-02", "Laag", f"{kind} {version}: ondersteuning stopt op {end}", where, line))


@check("F-02")
def eol(proj, meta):
    r = Result("F-02")
    found = False
    for p in proj.find(".nvmrc", ".node-version"):
        m = re.search(r"v?(\d+)", proj.text(p))
        if m:
            found = True
            _eol_check(r, "node", m.group(1), proj.rel(p))
    for p in proj.find(".python-version", "runtime.txt"):
        m = re.search(r"(\d+\.\d+)", proj.text(p))
        if m:
            found = True
            _eol_check(r, "python", m.group(1), proj.rel(p))
    for p in proj.find("Dockerfile", "Dockerfile.*", "*.dockerfile", "docker-compose*.yml"):
        for i, line in enumerate(proj.text(p).splitlines(), 1):
            for m in re.finditer(r"\b(node|python):(\d+(?:\.\d+)?)", line):
                found = True
                _eol_check(r, m.group(1), m.group(2), proj.rel(p), i)
    for p in proj.find("package.json"):
        d = proj.json(p) or {}
        eng = (d.get("engines") or {}).get("node")
        if eng:
            m = re.search(r"(\d+)", eng)
            if m and not re.match(r"\s*>=", eng):
                found = True
                _eol_check(r, "node", m.group(1), proj.rel(p))
    for c in all_components(proj):
        name = c.name if c.ecosystem == "npm" else norm_py(c.name)
        why = ref()["verouderd"].get(c.ecosystem, {}).get(name)
        if why and c.direct:
            r.add(Finding("F-02", "Middel", f"{c.name}: {why}", c.source))
        if c.version and c.direct:
            if c.ecosystem == "PyPI" and name == "django":
                _eol_check(r, "django", c.version, c.source)
            if c.ecosystem == "npm" and name in ("vue", "jquery"):
                _eol_check(r, name, c.version, c.source)
        found = found or bool(c)
    if not found:
        r.status, r.reden = "Niet gescand", "Geen runtimeversie of afhankelijkheden gevonden."
    r.info.append(f"Tabel met einddata: stand {ref()['stand']}.")
    return r


# ------------------------------------------------------------------ F-05
@check("F-05")
def licenses(proj, meta):
    r = Result("F-05")
    comps = all_components(proj)
    if not comps:
        r.status, r.reden = "Niet van toepassing", "Geen afhankelijkheden gevonden."
        return r
    # licenties aanvullen uit node_modules, als die er is
    for c in comps:
        if c.ecosystem == "npm" and not c.license:
            for pj in (proj.root / "node_modules" / c.name / "package.json",):
                try:
                    d = json.loads(pj.read_text())
                    lic = d.get("license")
                    c.license = lic if isinstance(lic, str) else (lic or {}).get("type")
                except Exception:
                    pass
    own = None
    for p in proj.find("package.json"):
        d = proj.json(p) or {}
        own = d.get("license") or ("UNLICENSED" if d.get("private") else own)
    lic_file = proj.find("LICENSE*", "LICENCE*", "COPYING*")
    own_text = proj.text(lic_file[0])[:400] if lic_file else ""
    copyleft_project = bool(re.search(r"GNU (Affero )?General Public", own_text)) or (own or "").upper().startswith(("GPL", "AGPL"))
    strong, weak = set(ref()["licenties"]["sterk"]), set(ref()["licenties"]["zwak"])
    known = 0
    for c in comps:
        if not c.license:
            continue
        known += 1
        ids = set(re.findall(r"[A-Za-z0-9.\-+]+", c.license))
        if ids & strong and not copyleft_project and not c.dev:
            r.add(Finding("F-05", "Hoog", f"{c.name} {c.version or ''} heeft een sterke copyleftlicentie ({c.license})",
                          c.source, bevestigen=True,
                          bewijs="Verenigbaarheid hangt af van hoe de software verspreid of aangeboden wordt."))
        elif ids & weak and not c.dev:
            r.add(Finding("F-05", "Laag", f"{c.name} {c.version or ''}: zwakke copyleft ({c.license})", c.source, bevestigen=True))
        elif c.license.upper() in ("UNLICENSED", "UNKNOWN", "SEE LICENSE IN LICENSE") and not c.dev:
            r.add(Finding("F-05", "Middel", f"{c.name} {c.version or ''}: licentie onduidelijk ({c.license})", c.source, bevestigen=True))
    r.info.append(f"Licentie bekend voor {known} van {len(comps)} componenten.")
    if known < len(comps) * 0.5:
        r.info.append("Van veel componenten is de licentie niet bekend zonder geïnstalleerde pakketten; "
                      "draai de scanner na 'npm ci' of 'pip install' voor een volledig beeld.")
        if known == 0:
            r.status, r.reden = "Niet gescand", "Geen licentiegegevens beschikbaar (pakketten niet geïnstalleerd)."
    return r


# ------------------------------------------------------------------ B-06
def _dl(a: str, b: str) -> int:
    """Damerau-Levenshtein-afstand (beperkt)."""
    if abs(len(a) - len(b)) > 2:
        return 3
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def _registry(eco, name, timeout=8):
    import requests
    try:
        if eco == "npm":
            u = "https://registry.npmjs.org/" + name.replace("/", "%2F")
            resp = requests.get(u, timeout=timeout, headers={"Accept": "application/vnd.npm.install-v1+json"})
            if resp.status_code == 404:
                return {"exists": False}
            full = requests.get("https://registry.npmjs.org/" + name.replace("/", "%2F"), timeout=timeout).json()
            return {"exists": True, "created": (full.get("time") or {}).get("created", "")[:10]}
        resp = requests.get(f"https://pypi.org/pypi/{name}/json", timeout=timeout)
        if resp.status_code == 404:
            return {"exists": False}
        rel = resp.json().get("releases", {})
        dates = [f["upload_time"][:10] for files in rel.values() for f in files if f.get("upload_time")]
        return {"exists": True, "created": min(dates) if dates else ""}
    except Exception:
        return None


@check("B-06")
def suspicious_packages(proj, meta):
    r = Result("B-06")
    comps = all_components(proj)
    if not comps:
        r.status, r.reden = "Niet van toepassing", "Geen afhankelijkheden gevonden."
        return r
    idx = advisories()["idx"]
    pop = {k: set(v) for k, v in ref()["populair"].items()}
    # 1. bekende kwaadaardige pakketten
    for c in comps:
        name = c.name if c.ecosystem == "npm" else norm_py(c.name)
        for rec in idx.get(c.ecosystem, {}).get(name, []):
            if rec.get("mal") and (not c.version or affected(c.ecosystem, c.version, rec)):
                r.add(Finding("B-06", "Kritiek", f"{c.name} {c.version or ''}: bekend kwaadaardig pakket", c.source,
                              bewijs=f"{rec['id']}: {rec.get('sum')}"))
    # 2. namen die op een populair pakket lijken
    for c in comps:
        if not c.direct:
            continue
        name = c.name if c.ecosystem == "npm" else norm_py(c.name)
        if name in pop.get(c.ecosystem, set()):
            continue
        for p in pop.get(c.ecosystem, set()):
            if len(p) < 4 or len(name) < 4 or name.startswith("@types/") or name.startswith(p + "-") or p.startswith(name + "-"):
                continue
            limit = 1 if len(p) <= 6 else 2
            dist = _dl(name, p)
            # toevoegingen vooraan of achteraan (grequests, expressjs) zijn meestal eigen pakketten
            edge_add = len(name) > len(p) and (name.endswith(p) or name.startswith(p))
            if p != name and dist <= limit and not edge_add:
                r.add(Finding("B-06", "Hoog", f"'{c.name}' lijkt sterk op het populaire pakket '{p}'", c.source,
                              bevestigen=True, bewijs="Mogelijke typosquatting of een tikfout van een AI-assistent."))
                break
    # 3. directe afhankelijkheden die niet in de lockfile staan (kon niet geïnstalleerd worden?)
    for m in all_manifests(proj):
        if m.lockfile and m.ecosystem == "npm" and m.components:
            locked = {c.name for c in m.components}
            for n in list(m.direct) + list(m.dev):
                if n not in locked:
                    r.add(Finding("B-06", "Middel", f"'{n}' staat in package.json maar niet in de lockfile", proj.rel(m.path),
                                  bevestigen=True, bewijs="Bestaat het pakket wel? Controleer of het geïnstalleerd kan worden."))
    # 4. bestaan en leeftijd in het register (alleen met netwerk)
    if proj.offline:
        r.info.append("Bestaan en leeftijd van pakketten niet nagekeken in het register (offline). "
                      "Draai met --online om verzonnen pakketten (slopsquatting) op te sporen.")
    else:
        checked = 0
        for c in comps:
            if not c.direct:
                continue
            info = _registry(c.ecosystem, c.name)
            if info is None:
                continue
            checked += 1
            if not info["exists"]:
                r.add(Finding("B-06", "Kritiek", f"'{c.name}' bestaat niet in het officiële register", c.source,
                              bewijs="Mogelijk een door AI verzonnen pakketnaam; wie die naam registreert, voert code uit bij jou."))
            elif info.get("created"):
                age = (dt.date.today() - dt.date.fromisoformat(info["created"])).days
                if age < 30:
                    r.add(Finding("B-06", "Hoog", f"'{c.name}' is pas {age} dagen geleden geregistreerd", c.source,
                                  bevestigen=True))
        r.info.append(f"{checked} directe afhankelijkheden nagekeken in het register.")
    r.info.append(f"{len(comps)} componenten vergeleken met de lijst van bekende kwaadaardige pakketten.")
    return r


# ------------------------------------------------------------------ C-19
PY_IMPORT_NAMES = {"beautifulsoup4": "bs4", "pyyaml": "yaml", "python-dotenv": "dotenv", "pillow": "PIL",
                   "scikit-learn": "sklearn", "opencv-python": "cv2", "psycopg2-binary": "psycopg2", "python-jose": "jose",
                   "pyjwt": "jwt", "attrs": "attr", "protobuf": "google.protobuf", "python-dateutil": "dateutil",
                   "pymysql": "pymysql", "typing-extensions": "typing_extensions", "faiss-cpu": "faiss",
                   "google-generativeai": "google.generativeai", "huggingface-hub": "huggingface_hub",
                   "python-multipart": "multipart", "email-validator": "email_validator", "mysqlclient": "MySQLdb"}
PY_TOOLS = {"gunicorn", "uvicorn", "wheel", "setuptools", "pip", "pytest", "black", "flake8", "mypy", "pylint", "isort",
            "coverage", "tox", "pre-commit", "ruff", "twine", "build", "pytest-cov", "ipython", "jupyter", "psycopg2-binary",
            "psycopg2", "mysqlclient", "gevent", "eventlet", "waitress", "whitenoise", "python-multipart", "email-validator"}
JS_IMPLICIT = re.compile(r"^(@types/|@angular/|@nestjs/|@cyclonedx/|zone\.js$|tslib$|core-js|regenerator-runtime|@babel/runtime|"
                         r"eslint|prettier|typescript$|ts-node|nodemon|husky|lint-staged|jest|vitest|mocha|"
                         r"babel|@babel/|webpack|vite|rollup|esbuild|postcss|autoprefixer|tailwindcss|sass$|less$|"
                         r"@vitejs/|@angular/cli|@angular-devkit|cross-env|concurrently|rimraf|pm2|serve$|http-server)")


@check("C-19")
def unused(proj, meta):
    r = Result("C-19")
    ms = all_manifests(proj)
    if not ms:
        r.status, r.reden = "Niet van toepassing", "Geen afhankelijkheden gevonden."
        return r
    js_src = "\n".join(proj.text(p) for p in proj.source_files({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".json"})
                       if p.name not in ("package.json", "package-lock.json", "npm-shrinkwrap.json"))
    py_src = "\n".join(proj.text(p) for p in proj.source_files({".py", ".cfg", ".ini", ".toml", ".txt", ".yml", ".yaml"}
                                                               ) if not p.name.startswith("requirements"))
    for m in ms:
        if m.ecosystem == "npm":
            pkg = proj.json(m.path) or {}
            scripts = " ".join((pkg.get("scripts") or {}).values())
            for n in m.direct:
                if JS_IMPLICIT.match(n):
                    continue
                pat = re.compile(r"""(['"`]|node_modules/|~)""" + re.escape(n) + r"""([/:@][^'"`]*)?['"`]""")
                if not pat.search(js_src) and n not in scripts:
                    r.add(Finding("C-19", meta["ernst"], f"'{n}' lijkt nergens gebruikt te worden", proj.rel(m.path),
                                  bevestigen=True, bewijs="Geen import, require of verwijzing gevonden in de broncode."))
        else:
            if len(m.direct) >= 15 and all(v.startswith("==") for v in m.direct.values()):
                r.info.append(f"{proj.rel(m.path)} lijkt een volledige 'pip freeze': directe en indirecte afhankelijkheden zijn niet te "
                              "onderscheiden, dus ongebruikte pakketten worden hier niet gemeld.")
                continue
            for n in m.direct:
                nn = norm_py(n)
                if nn in PY_TOOLS:
                    continue
                mod = PY_IMPORT_NAMES.get(nn, nn.replace("-", "_"))
                top = mod.split(".")[0]
                pat = re.compile(r"(^|\n)\s*(import|from)\s+" + re.escape(top) + r"\b|['\"]" + re.escape(top) + r"['\".]", re.I)
                if not pat.search(py_src):
                    r.add(Finding("C-19", meta["ernst"], f"'{n}' lijkt nergens gebruikt te worden", proj.rel(m.path),
                                  bevestigen=True, bewijs=f"Geen 'import {top}' gevonden in de broncode."))
    return r
