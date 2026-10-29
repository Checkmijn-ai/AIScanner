"""API voor aiscan: sessiecodes, bewijs inleveren, scorepagina en badge.

Eindpunten
  GET  /api/v1/versie            manifest van de dagversie (latest.json)
  POST /api/v1/sessie            nieuwe sessiecode (nonce), 2 uur geldig, één keer bruikbaar
  POST /api/v1/resultaat         bewijs.json inleveren; geeft de scorepagina en de badge terug
  GET  /api/v1/score/<id>        de score als JSON
  GET  /score/<id>               publieke scorepagina
  GET  /score/<id>.svg           badge voor een README of website
  POST /api/v1/rapport           versleuteld volledig rapport inleveren (alleen vanuit GitHub Actions, met OIDC-token)
  GET  /api/v1/rapport/<id>      het versleutelde rapport ophalen; ontsleutelen gebeurt in de browser

Versleutelde rapporten
  De Action versleutelt het rapport met AES-256-GCM en een willekeurige sleutel die alleen in de link staat
  (https://checkmijn.ai/rapport/<id>#k=<sleutel>). Het deel na # gaat nooit naar een server. Wij bewaren dus
  alleen gegevens die we niet kunnen lezen, plus het nummer van de repository (om te beperken en later aan een
  account te koppelen). Niet aan een account gekoppelde rapporten worden na RAPPORT_DAGEN dagen gewist.

Wat de API controleert bij een bewijs
  - formaat en verplichte velden;
  - de sessiecode bestaat, is niet verlopen en niet eerder gebruikt;
  - de scanner is een gepubliceerde dagversie (controlegetal) van hoogstens MAX_LEEFTIJD dagen oud;
  - de regelset in het bewijs hoort bij die dagversie;
  - het bewijs bevat precies de checks van die dagversie, met geldige statussen;
  - de score klopt met de resultaten (de API rekent ze zelf opnieuw uit).
Wat de API niet kan aantonen: dat niemand op zijn eigen machine met de scanner of het bewijs knoeide.
Daarom is elke score via deze route een "Zelfscan" (hoogstens C). Een geverifieerde scan komt via een attestation van
GitHub Actions of GitLab CI (zie README, nog te bouwen).

Starten (ontwikkeling):  AISCAN_PUBLIC=/var/www/aiscan AISCAN_DB=/var/lib/aiscan/aiscan.db flask --app platform/api.py run
Productie: achter een reverse proxy met HTTPS, bv. gunicorn -w 2 'platform.api:app' (zie README).
"""
from __future__ import annotations

import datetime as dt
import html
import json
import os
import secrets
import sqlite3
import sys
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from flask import Flask, Response, abort, g, jsonify, render_template, request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "platform"))
from aiscan.score import OUD_NAAR_NIEUW, uit_bewijs  # noqa: E402

PUBLIC = Path(os.environ.get("AISCAN_PUBLIC", ROOT / "public"))
# Staat de dagversie elders (bv. GitHub Pages), dan haalt de API latest.json en versies.json daar op.
PUBLIC_URL = os.environ.get("AISCAN_PUBLIC_URL", "").rstrip("/")
_CACHE: dict = {}
DB = Path(os.environ.get("AISCAN_DB", ROOT / "aiscan.db"))
SITE = os.environ.get("AISCAN_SITE", "http://localhost:5000").rstrip("/")
MAX_LEEFTIJD = int(os.environ.get("AISCAN_MAX_LEEFTIJD_DAGEN", "7"))
NONCE_GELDIG = dt.timedelta(hours=2)
SCORE_GELDIG = dt.timedelta(days=int(os.environ.get("AISCAN_SCORE_GELDIG_DAGEN", "30")))
LIMIET_PER_UUR = int(os.environ.get("AISCAN_LIMIET_PER_UUR", "60"))
STATUSSEN = {"Geen bevinding", "Bevinding", "Niet van toepassing", "Niet gescand", "Gehaald"}  # "Gehaald" = oude naam (tot 2026-10-20)
ERNST = {None, "Info", "Laag", "Middel", "Hoog", "Kritiek"}
KLEUR = {"A": "#1b7f3b", "B": "#4f9d2a", "C": "#97a91d", "D": "#c9a200", "E": "#e07f12", "F": "#d9480f", "G": "#b1161a"}

app = Flask(__name__, template_folder=str(ROOT / "platform" / "templates"), static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024  # versleuteld rapport; een bewijs wordt apart beperkt
MAX_BEWIJS = 256 * 1024  # een bewijs is klein; nooit code
MAX_RAPPORT = 5 * 1024 * 1024
RAPPORT_DAGEN = int(os.environ.get("AISCAN_RAPPORT_DAGEN", "90"))
RAPPORTEN_PER_DAG = int(os.environ.get("AISCAN_RAPPORTEN_PER_DAG", "50"))  # per repository
OIDC_ISSUER = os.environ.get("AISCAN_OIDC_ISSUER", "https://token.actions.githubusercontent.com")
OIDC_JWKS = os.environ.get("AISCAN_OIDC_JWKS", OIDC_ISSUER + "/.well-known/jwks")
OIDC_AUD = os.environ.get("AISCAN_OIDC_AUD", "checkmijn.ai")
SITE_ORIGIN = os.environ.get("AISCAN_SITE_ORIGIN", "https://checkmijn.ai")


# ------------------------------------------------------------------ opslag
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.executescript("""
            CREATE TABLE IF NOT EXISTS sessies (nonce TEXT PRIMARY KEY, aangemaakt TEXT, gebruikt INTEGER DEFAULT 0, ip TEXT);
            CREATE TABLE IF NOT EXISTS scores (id TEXT PRIMARY KEY, aangemaakt TEXT, geldig_tot TEXT, letter TEXT, soort TEXT,
                project TEXT, commit_hash TEXT, boom TEXT, dagversie TEXT, databank TEXT, bewijs TEXT);
            CREATE TABLE IF NOT EXISTS rapporten (id TEXT PRIMARY KEY, aangemaakt TEXT, verloopt TEXT,
                repo_id TEXT, iv TEXT, data TEXT, grootte INTEGER, account TEXT);
            CREATE INDEX IF NOT EXISTS rapporten_repo ON rapporten (repo_id, aangemaakt);
            CREATE TABLE IF NOT EXISTS tel_projecten (project TEXT PRIMARY KEY, eerste TEXT, eerste_op TEXT,
                laatste TEXT, laatste_op TEXT, scans INTEGER DEFAULT 0, dag TEXT, dag_scans INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS tel_dagen (dag TEXT PRIMARY KEY, scans INTEGER DEFAULT 0);
        """)
        for sql in ("ALTER TABLE sessies ADD COLUMN geteld INTEGER DEFAULT 0",
                    "ALTER TABLE tel_projecten ADD COLUMN bron TEXT DEFAULT 'github'",
                    "ALTER TABLE tel_dagen ADD COLUMN zelf INTEGER DEFAULT 0",
                    "ALTER TABLE scores ADD COLUMN status TEXT",
                    "ALTER TABLE scores ADD COLUMN status_reden TEXT",
                    "ALTER TABLE scores ADD COLUMN status_op TEXT"):
            try:
                g.db.execute(sql)
            except sqlite3.OperationalError:
                pass  # bestaat al
        _migreer(g.db)
    return g.db


def _migreer(c):
    """Eenmalig: zelfscans van vóór 22 oktober 2026 naar de nieuwe schaal (hoogstens C) omzetten."""
    c.execute("CREATE TABLE IF NOT EXISTS migraties (naam TEXT PRIMARY KEY, op TEXT)")
    if not c.execute("SELECT 1 FROM migraties WHERE naam = 'geen-ip'").fetchone():
        try:
            c.execute("UPDATE sessies SET ip = NULL")  # IP-adressen van oudere sessiecodes wissen
        except sqlite3.OperationalError:
            pass  # nog geen tabel sessies
        c.execute("INSERT INTO migraties VALUES ('geen-ip', ?)", (nu().isoformat(timespec="seconds"),))
        c.commit()
    if c.execute("SELECT 1 FROM migraties WHERE naam = 'zelfscan-tot-c'").fetchone():
        return
    # in Python omzetten en met parameters terugschrijven: elke rij precies één keer
    for rid, letter in c.execute("SELECT id, letter FROM scores WHERE soort = 'Zelfcontrole'").fetchall():
        c.execute("UPDATE scores SET letter = ?, soort = 'Zelfscan' WHERE id = ?", (OUD_NAAR_NIEUW.get(letter, letter), rid))
    for proj, eerste, laatste in c.execute("SELECT project, eerste, laatste FROM tel_projecten").fetchall():
        c.execute("UPDATE tel_projecten SET eerste = ?, laatste = ? WHERE project = ?",
                  (OUD_NAAR_NIEUW.get(eerste, eerste), OUD_NAAR_NIEUW.get(laatste, laatste), proj))
    c.execute("INSERT INTO migraties VALUES ('zelfscan-tot-c', ?)", (nu().isoformat(timespec="seconds"),))
    c.commit()


@app.teardown_appcontext
def _close(exc):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def nu():
    return dt.datetime.now(dt.timezone.utc)


# ------------------------------------------------------------------ eenvoudige limiet per IP
_HITS = defaultdict(deque)
_LOCK = threading.Lock()


def limiet():
    # Achter Cloudflare: CF-Connecting-IP is het echte adres. Anders het eerste adres uit X-Forwarded-For (Caddy).
    ip = (request.headers.get("CF-Connecting-IP")
          or request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0]).strip()
    t = time.time()
    with _LOCK:
        q = _HITS[ip]
        while q and q[0] < t - 3600:
            q.popleft()
        if len(q) >= LIMIET_PER_UUR:
            abort(Response(json.dumps({"fout": "Te veel aanvragen; probeer later opnieuw."}), 429, mimetype="application/json"))
        q.append(t)
    return ip


def fout(msg, code=422):
    return jsonify({"fout": msg}), code


def lees(naam):
    if PUBLIC_URL:
        import time
        import urllib.request
        tijd, inhoud = _CACHE.get(naam, (0, None))
        if time.time() - tijd > 600 or inhoud is None:
            try:
                with urllib.request.urlopen(f"{PUBLIC_URL}/{naam}", timeout=10) as r:
                    inhoud = json.loads(r.read())
                _CACHE[naam] = (time.time(), inhoud)
            except Exception:
                if inhoud is None:
                    abort(Response(json.dumps({"fout": f"{naam} is nu niet bereikbaar; probeer later opnieuw"}), 503,
                                   mimetype="application/json"))
        return inhoud
    p = PUBLIC / naam
    if not p.exists():
        abort(Response(json.dumps({"fout": f"{naam} ontbreekt op de server; draai eerst build_daily.py"}), 503,
                       mimetype="application/json"))
    return json.loads(p.read_text())


def lees_tekst(naam: str) -> bytes:
    """Een bestand van de dagversie (scan.md, latest.json, ...), van GitHub Pages of lokaal, 10 minuten in de cache."""
    if PUBLIC_URL:
        import urllib.request
        tijd, inhoud = _CACHE.get(("raw", naam), (0, None))
        if time.time() - tijd > 600 or inhoud is None:
            try:
                with urllib.request.urlopen(f"{PUBLIC_URL}/{naam}", timeout=10) as r:
                    inhoud = r.read()
                _CACHE[("raw", naam)] = (time.time(), inhoud)
            except Exception:
                if inhoud is None:
                    abort(Response(f"{naam} is nu niet bereikbaar; probeer later opnieuw", 503, mimetype="text/plain"))
        return inhoud
    p = PUBLIC / naam
    if not p.exists():
        abort(404)
    return p.read_bytes()


DAGVERSIE_BESTANDEN = {"scan.md": "text/markdown; charset=utf-8", "latest.json": "application/json",
                       "checks.json": "application/json", "versies.json": "application/json",
                       "changelog.json": "application/json", "public-key.pem": "text/plain; charset=utf-8",
                       "checkmijn.yml": "text/plain; charset=utf-8", "checkmijn-schrijven.yml": "text/plain; charset=utf-8",
                       "geen-code.json": "application/json",
                       "testbank.json": "application/json"}


def _dagversie_bestand(naam):
    def view():
        return Response(lees_tekst(naam), mimetype=DAGVERSIE_BESTANDEN[naam],
                        headers={"Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=300"})
    view.__name__ = "dagversie_" + naam.replace(".", "_").replace("-", "_")
    return view


for _naam in DAGVERSIE_BESTANDEN:
    app.add_url_rule(f"/{_naam}", view_func=_dagversie_bestand(_naam))


@app.get("/checkmijn-<dag>.pyz")
def scanner_pyz(dag):
    """De scanner zelf, ook via checkmijn.ai: zo heeft een AI-agent maar één domein nodig. Alleen de huidige dagversie."""
    m = json.loads(lees_tekst("latest.json"))
    if f"checkmijn-{dag}.pyz" != m.get("bestand"):
        abort(404)
    return Response(lees_tekst(m["bestand"]), mimetype="application/zip",
                    headers={"Cache-Control": "public, max-age=3600", "Content-Disposition": f'attachment; filename="{m["bestand"]}"'})


# ------------------------------------------------------------------ API
@app.get("/api/v1/versie")
def versie():
    return jsonify(lees("latest.json"))


@app.post("/api/v1/sessie")
def sessie():
    limiet()
    nonce = secrets.token_urlsafe(18)
    # Geen IP-adres bewaren (alleen kort in het geheugen voor de limiet); oude sessiecodes na 7 dagen weg.
    db().execute("INSERT INTO sessies (nonce, aangemaakt, ip) VALUES (?, ?, NULL)", (nonce, nu().isoformat()))
    db().execute("DELETE FROM sessies WHERE aangemaakt < ?", ((nu() - dt.timedelta(days=7)).isoformat(),))
    db().commit()
    m = lees("latest.json")
    return jsonify({"nonce": nonce, "geldig_tot": (nu() + NONCE_GELDIG).isoformat(timespec="seconds"),
                    "dagversie": m["dagversie"], "download": m["url"], "sha256": m["sha256"]})


def controleer_bewijs(b, voor_telling: bool = False):
    """Controleert een bewijsbestand (sessiecode, scanner, resultaten, score). Geeft (fout, dag, eigen) terug."""
    if not isinstance(b, dict) or b.get("formaat") != "aiscan-bewijs/1":
        return fout("Geen geldig bewijsbestand (formaat aiscan-bewijs/1 verwacht)."), None, None
    for veld in ("nonce", "scanner", "project", "resultaten", "score"):
        if veld not in b:
            return fout(f"Veld '{veld}' ontbreekt."), None, None
    row = db().execute("SELECT * FROM sessies WHERE nonce = ?", (str(b["nonce"]),)).fetchone()
    if not row:
        return fout("Onbekende sessiecode. Vraag een nieuwe via /api/v1/sessie."), None, None
    if voor_telling and row["geteld"]:
        return fout("Deze scan is al meegeteld."), None, None
    if not voor_telling and row["gebruikt"]:
        return fout("Deze sessiecode is al gebruikt. Elke scan heeft een nieuwe sessiecode nodig."), None, None
    if nu() - dt.datetime.fromisoformat(row["aangemaakt"]) > NONCE_GELDIG:
        return fout("Sessiecode verlopen (2 uur). Vraag een nieuwe en scan opnieuw."), None, None
    versies = lees("versies.json")
    sc = b["scanner"]
    dag = next((d for d, v in versies.items() if v["sha256"] == sc.get("sha256")), None)
    if not dag:
        return fout("Onbekende scanner: het controlegetal hoort bij geen gepubliceerde dagversie. Gebruik de instructie van vandaag."), None, None
    if (nu().date() - dt.date.fromisoformat(dag)).days > MAX_LEEFTIJD:
        return fout(f"Dagversie {dag} is ouder dan {MAX_LEEFTIJD} dagen. Gebruik de instructie van vandaag."), None, None
    v = versies[dag]
    if v.get("regelset") and sc.get("regelset") != v["regelset"]:
        return fout("De regelset in het bewijs hoort niet bij deze dagversie."), None, None
    res = b["resultaten"]
    if not isinstance(res, list) or sorted(r.get("id") for r in res) != sorted(v["checks"]):
        return fout("Het bewijs bevat niet precies de checks van deze dagversie."), None, None
    for r in res:
        if r.get("status") not in STATUSSEN or r.get("zwaarste") not in ERNST or not isinstance(r.get("aantal"), int):
            return fout(f"Ongeldig resultaat voor {r.get('id')}."), None, None
        if r["status"] == "Bevinding" and (r["aantal"] < 1 or r["zwaarste"] is None):
            return fout(f"Tegenstrijdig resultaat voor {r['id']}."), None, None
        if r["status"] != "Bevinding" and r["zwaarste"] not in (None, "Info"):
            return fout(f"Tegenstrijdig resultaat voor {r['id']}."), None, None
    # Via deze route is elke score een zelfscan (niveau 1, hoogstens C), wat het bewijs ook als niveau opgeeft.
    eigen = uit_bewijs(res, 1)
    # Een scanner van vóór 22 oktober 2026 gaf nog de oude letter (hoogstens B). Die aanvaarden we, maar we bewaren de nieuwe.
    if b["score"].get("letter") not in (eigen["letter"], eigen["oude_letter"]):
        return fout("De score in het bewijs klopt niet met de resultaten."), None, None
    return None, dag, eigen


@app.post("/api/v1/resultaat")
def resultaat():
    if (request.content_length or 0) > MAX_BEWIJS:
        return fout("Een bewijs is hoogstens 256 kB.", 413)
    limiet()
    b = request.get_json(silent=True)
    f, dag, eigen = controleer_bewijs(b)
    if f:
        return f
    sc = b["scanner"]

    sid = secrets.token_hex(5)
    soort = "Zelfscan"
    geldig = nu() + SCORE_GELDIG
    pr = b["project"]
    db().execute("UPDATE sessies SET gebruikt = 1 WHERE nonce = ?", (b["nonce"],))
    db().execute("INSERT INTO scores (id, aangemaakt, geldig_tot, letter, soort, project, commit_hash, boom, dagversie, databank, bewijs) "
                 "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                 (sid, nu().isoformat(timespec="seconds"), geldig.isoformat(timespec="seconds"), eigen["letter"], soort,
                  str(pr.get("naam") or "")[:120], str(pr.get("commit") or "")[:64], str(pr.get("boom_sha256") or "")[:64],
                  dag, str(sc.get("databank") or ""), json.dumps(b)))
    db().commit()
    return jsonify({"id": sid, "score": eigen["letter"], "soort": soort, "dekking": eigen["dekking"],
                    "geldig_tot": geldig.date().isoformat(), "pagina": f"{SITE}/score/{sid}", "badge": f"{SITE}/score/{sid}.svg",
                    "markdown": f"[![Scanscore {eigen['letter'] or '-'}]({SITE}/score/{sid}.svg)]({SITE}/score/{sid})"}), 201


def _score(sid):
    row = db().execute("SELECT * FROM scores WHERE id = ?", (sid,)).fetchone()
    if not row:
        abort(404)
    return row


def registerstatus(r) -> tuple[str, str]:
    """Status in het publieke register: (status, uitleg). Ingetrokken of geschorst gaat voor verlopen."""
    st = r["status"] if "status" in r.keys() else None
    if st in ("ingetrokken", "geschorst"):
        return st.capitalize(), (r["status_reden"] or "") + (f" (sinds {r['status_op'][:10]})" if r["status_op"] else "")
    if nu().isoformat() > r["geldig_tot"]:
        return "Verlopen", f"De score gold tot {r['geldig_tot'][:10]}. Een nieuwe scan geeft een nieuwe score."
    return "Geldig", f"Geldig tot {r['geldig_tot'][:10]}."


def auditgegevens(r, b) -> dict:
    """Wat een auditor nodig heeft om de score in zijn dossier op te nemen: status, periode, normversie,
    versie per check, koppeling met ISO 27001 en wat erbuiten valt."""
    try:
        dagv = lees("versies.json").get(r["dagversie"], {})
    except Exception:  # noqa: BLE001  (dagversie niet bereikbaar: de pagina werkt dan zonder versie per check)
        dagv = {}
    cat = {c["id"]: c for c in lees("checks.json")["checks"]}
    n = _site_mod.norm()
    normtekst = {c["id"]: c["wat"] for c in n["checks"]}
    versies = dagv.get("checkversies")
    status, uitleg = registerstatus(r)
    checks = []
    for x in sorted(b["resultaten"], key=lambda x: x["id"]):
        c = cat.get(x["id"], {})
        checks.append({"id": x["id"], "wat": c.get("scan", ""), "status": "Geen bevinding" if x["status"] == "Gehaald" else x["status"],
                       "versie": (versies or {}).get(x["id"], c.get("versie")),
                       "drempel": "voorstel" if "voorstel" in normtekst.get(x["id"], "").lower() else "vast"})
    per = {c["id"]: c for c in checks}
    cw = _site_mod.crosswalk()
    annex = []
    for x in cw["iso27001"]:
        hier = [per[c] for c in x["checks"] if c in per]
        if not hier:
            continue
        st = ("bevinding" if any(c["status"] == "Bevinding" for c in hier)
              else "geen bevinding" if any(c["status"] == "Geen bevinding" for c in hier) else "niet gescand")
        annex.append({"id": x["id"], "titel": x["titel"], "dekking": x["dekking"], "checks": [c["id"] for c in hier],
                      "uitslag": st, "alle_checks": len(x["checks"])})
    return {
        "status": status, "status_uitleg": uitleg,
        "periode": {"van": r["aangemaakt"][:10], "tot": r["aangemaakt"][:10], "soort": "momentopname"},
        "normversie": dagv.get("normversie") or str(n["versie"]), "normversie_bekend": bool(dagv.get("normversie")),
        "versie_per_check_bekend": bool(versies),
        "regelset": (b.get("scanner") or {}).get("regelset") or dagv.get("regelset"),
        "crosswalkversie": cw["versie"],
        "checks": checks, "iso27001": annex,
        "buiten": [{"id": x["id"], "titel": x["titel"]} for x in cw["iso27001"] if x["dekking"] == "niet"],
    }


@app.get("/api/v1/score/<sid>")
def score_json(sid):
    r = _score(sid)
    b = json.loads(r["bewijs"])
    a = auditgegevens(r, b)
    return jsonify({"id": r["id"], "score": r["letter"], "soort": r["soort"], "project": r["project"],
                    "commit": r["commit_hash"], "dagversie": r["dagversie"], "databank": r["databank"],
                    "aangemaakt": r["aangemaakt"], "geldig_tot": r["geldig_tot"], "verlopen": nu().isoformat() > r["geldig_tot"],
                    "status": a["status"], "status_uitleg": a["status_uitleg"], "periode": a["periode"],
                    "normversie": a["normversie"], "regelset": a["regelset"], "crosswalkversie": a["crosswalkversie"],
                    "checks": [{k: c[k] for k in ("id", "status", "versie", "drempel")} for c in a["checks"]],
                    "iso27001": [{k: x[k] for k in ("id", "dekking", "checks", "uitslag")} for x in a["iso27001"]],
                    "ernst": b.get("ernst"), "resultaten": b.get("resultaten")})


@app.get("/score/<sid>.svg")
def badge(sid):
    r = _score(sid)
    dekking = uit_bewijs(json.loads(r["bewijs"]).get("resultaten", []), 1)["dekking"]
    status, _ = registerstatus(r)
    return Response(badge_svg(r["letter"], r["soort"], status != "Geldig", r["project"], r["aangemaakt"][:10], dekking,
                              staat=status.lower()),
                    mimetype="image/svg+xml", headers={"Cache-Control": "max-age=3600"})


def badge_svg(letter, soort: str, verlopen: bool, project: str = "", datum: str = "", dekking: float | None = None,
              staat: str = "verlopen") -> str:
    """Twee vormen, zodat niemand een zelfscan verwart met een keuring:
    zelfscan = gestippelde rand, letter als omlijning, het woord ZELFSCAN; keuring = volle kleur, gevulde letter."""
    zelf = soort in ("Zelfscan", "Zelfcontrole")
    woord = "ZELFSCAN" if zelf else "GEKEURD"
    staat = f" · {staat}" if verlopen else ""
    kleur = "#8a94a6" if verlopen or not letter else KLEUR[letter]
    L = html.escape(letter or "–")
    tekst = woord + (staat or (f" · {round(dekking * 100)}%" if dekking is not None else ""))
    wl, wr = 74, 34 + int(7.6 * len(tekst))
    titel = html.escape(f"Scanscore {letter or '–'} · {woord.lower()}{staat}"
                        + (f" · {round(dekking * 100)}% van de checks gecontroleerd" if dekking is not None else "") + f" · {project} · {datum}")
    kop = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{wl + wr}" height="22" role="img" aria-label="{titel}">'
           f'<title>{titel}</title><rect width="{wl}" height="22" rx="3" fill="#15203a"/>')
    if zelf:
        rechts = (f'<rect x="{wl + 0.75}" y="0.75" width="{wr - 1.5}" height="20.5" rx="3" fill="#fff" stroke="{kleur}" '
                  f'stroke-width="1.5" stroke-dasharray="3 2"/>'
                  f'<text x="{wl + 13}" y="16" text-anchor="middle" font-size="14" font-weight="bold" fill="#fff" '
                  f'stroke="{kleur}" stroke-width="1.1">{L}</text>'
                  f'<text x="{wl + 26}" y="15" font-size="10" font-weight="bold" fill="#15203a" letter-spacing=".4">{tekst}</text>')
    else:
        rechts = (f'<rect x="{wl}" width="{wr}" height="22" rx="3" fill="{kleur}"/><rect x="{wl - 3}" width="6" height="22" fill="{kleur}"/>'
                  f'<text x="{wl + 13}" y="16" text-anchor="middle" font-size="14" font-weight="bold" fill="#fff">{L}</text>'
                  f'<text x="{wl + 26}" y="15" font-size="10" font-weight="bold" fill="#fff" letter-spacing=".4">{tekst}</text>')
    return (kop + '<g font-family="Verdana,DejaVu Sans,sans-serif">'
            f'<text x="9" y="15" font-size="11" fill="#fff">Scanscore</text>{rechts}</g></svg>')


@app.get("/score/<sid>")
def pagina(sid):
    r = _score(sid)
    b = json.loads(r["bewijs"])
    cat = {c["id"]: c for c in lees("checks.json")["checks"]}
    domeinen = {}
    for x in b["resultaten"]:
        dname = cat.get(x["id"], {}).get("domein", x["id"][0])
        d = domeinen.setdefault(dname, {"Geen bevinding": 0, "Bevinding": 0, "Niet van toepassing": 0, "Niet gescand": 0})
        d["Geen bevinding" if x["status"] == "Gehaald" else x["status"]] += 1
    a = auditgegevens(r, b)
    return render_template("score.html", r=r, b=b, domeinen=sorted(domeinen.items()), kleur=KLEUR, eigen=uit_bewijs(b["resultaten"], 1),
                           verlopen=a["status"] != "Geldig", site=SITE, a=a)


@app.get("/score/<sid>/verklaring")
def verklaring(sid):
    """Sjabloon voor een overbruggingsverklaring (bridge letter): de eigenaar verklaart wat er sinds de scan veranderde.
    CheckMijn.AI geeft deze verklaring niet af; ze is ingevuld met de gegevens van de score."""
    r = _score(sid)
    b = json.loads(r["bewijs"])
    return render_template("verklaring.html", r=r, b=b, a=auditgegevens(r, b), site=SITE, vandaag=nu().date().isoformat())


# ------------------------------------------------------------------ versleutelde rapporten
_JWKS: dict = {"tijd": 0, "sleutels": {}}


def _b64url(s: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def oidc_claims(token: str) -> dict:
    """Controleert een OIDC-token van GitHub Actions (RS256) en geeft de claims terug."""
    import urllib.request
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    try:
        kop_b, inhoud_b, sig_b = token.split(".")
        kop = json.loads(_b64url(kop_b))
        claims = json.loads(_b64url(inhoud_b))
    except Exception:
        raise ValueError("ongeldig token")
    if kop.get("alg") != "RS256":
        raise ValueError("onbekend algoritme")
    if time.time() - _JWKS["tijd"] > 3600 or kop.get("kid") not in _JWKS["sleutels"]:
        with urllib.request.urlopen(OIDC_JWKS, timeout=10) as r:
            _JWKS["sleutels"] = {k["kid"]: k for k in json.loads(r.read())["keys"] if k.get("kty") == "RSA"}
        _JWKS["tijd"] = time.time()
    jwk = _JWKS["sleutels"].get(kop.get("kid"))
    if not jwk:
        raise ValueError("onbekende sleutel")
    pub = rsa.RSAPublicNumbers(int.from_bytes(_b64url(jwk["e"]), "big"), int.from_bytes(_b64url(jwk["n"]), "big")).public_key()
    pub.verify(_b64url(sig_b), f"{kop_b}.{inhoud_b}".encode(), padding.PKCS1v15(), hashes.SHA256())
    t = time.time()
    if claims.get("iss") != OIDC_ISSUER:
        raise ValueError("verkeerde uitgever")
    aud = claims.get("aud")
    if OIDC_AUD not in (aud if isinstance(aud, list) else [aud]):
        raise ValueError("verkeerde doelgroep")
    if not (claims.get("nbf", 0) - 60 <= t <= claims.get("exp", 0) + 60):
        raise ValueError("verlopen token")
    if not claims.get("repository_id"):
        raise ValueError("geen repository in het token")
    return claims


def _ruim_op():
    db().execute("DELETE FROM rapporten WHERE account IS NULL AND verloopt < ?", (nu().isoformat(),))
    db().commit()


@app.post("/api/v1/rapport")
def rapport_inleveren():
    limiet()
    if (request.content_length or 0) > MAX_RAPPORT + 4096:
        return fout("Het rapport is te groot (hoogstens 5 MB).", 413)
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return fout("Alleen vanuit GitHub Actions, met een OIDC-token (permissions: id-token: write).", 401)
    try:
        claims = oidc_claims(auth[7:].strip())
    except Exception as e:  # noqa: BLE001
        return fout(f"Token geweigerd: {e}.", 401)
    b = request.get_json(silent=True) or {}
    iv, data = b.get("iv"), b.get("data")
    if b.get("versie") != 1 or b.get("alg") != "A256GCM" or not isinstance(iv, str) or not isinstance(data, str):
        return fout("Verwacht: {versie: 1, alg: 'A256GCM', iv, data} (base64url).")
    try:
        if len(_b64url(iv)) != 12 or len(_b64url(data)) < 17:
            raise ValueError
    except Exception:
        return fout("iv of data is geen geldige base64url.")
    repo_id = str(claims["repository_id"])
    _ruim_op()
    dag = (nu() - dt.timedelta(days=1)).isoformat()
    n = db().execute("SELECT COUNT(*) FROM rapporten WHERE repo_id = ? AND aangemaakt > ?", (repo_id, dag)).fetchone()[0]
    if n >= RAPPORTEN_PER_DAG:
        return fout("Te veel rapporten voor deze repository vandaag.", 429)
    rid = secrets.token_urlsafe(16)
    verloopt = nu() + dt.timedelta(days=RAPPORT_DAGEN)
    db().execute("INSERT INTO rapporten (id, aangemaakt, verloopt, repo_id, iv, data, grootte) VALUES (?,?,?,?,?,?,?)",
                 (rid, nu().isoformat(), verloopt.isoformat(), repo_id, iv, data, len(data)))
    db().commit()
    return jsonify({"id": rid, "pagina": f"{SITE_ORIGIN}/rapport/{rid}", "verloopt": verloopt.date().isoformat()}), 201


# ------------------------------------------------------------------ openbare statistiek (checkmijn.ai/resultaten)
# Alleen scans die via GitHub Actions komen (ondertekend OIDC-token) en waarvan de eigenaar `meetellen: true` zette.
# We bewaren per project een onomkeerbare code (HMAC van het repository-id met een geheime zout), de eerste en de
# laatste letter, en het aantal scans. Geen naam, geen code, geen bevindingen.
LETTERS = "ABCDEFG"
TEL_PER_DAG = 10  # meer scans per project per dag tellen niet mee (geen opblazen van de teller)


def _zout() -> bytes:
    z = os.environ.get("CHECKMIJN_TELLING_ZOUT", "").encode()
    if z:
        return z
    p = DB.parent / "telling-zout"
    if not p.exists():
        p.write_bytes(secrets.token_bytes(32))
        p.chmod(0o600)
    return p.read_bytes()


def project_code(repo_id: str) -> str:
    import hashlib
    import hmac
    return hmac.new(_zout(), f"github:{repo_id}".encode(), hashlib.sha256).hexdigest()[:32]


@app.post("/api/v1/telling")
def telling():
    limiet()
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return fout("Alleen vanuit GitHub Actions, met een OIDC-token (permissions: id-token: write).", 401)
    try:
        claims = oidc_claims(auth[7:].strip())
    except Exception as e:  # noqa: BLE001
        return fout(f"Token geweigerd: {e}.", 401)
    if str(claims.get("event_name", "")).startswith("pull_request"):
        return jsonify({"geteld": False, "melding": "Pull requests tellen niet mee."}), 200
    if claims.get("event_name") == "schedule":  # de dagelijkse lekkenwacht is geen nieuwe scan door de eigenaar
        return jsonify({"geteld": False, "melding": "Dagelijkse controles tellen niet mee."}), 200
    d = request.get_json(silent=True) or {}
    letter = str(d.get("letter", ""))
    if len(letter) != 1 or letter not in LETTERS:
        return fout("Verwacht: {letter: A–G}.")
    if d.get("schaal") != "zelfscan":  # een oudere action: letter van de oude schaal (hoogstens B)
        letter = OUD_NAAR_NIEUW[letter]
    if letter in "AB":
        return fout("Een zelfscan haalt hoogstens een C.")
    return tel(project_code(str(claims["repository_id"])), letter, "github")


def tel(project: str, letter: str, bron: str):
    t = nu()
    dag = t.date().isoformat()
    r = db().execute("SELECT dag, dag_scans FROM tel_projecten WHERE project = ?", (project,)).fetchone()
    if r and r["dag"] == dag and r["dag_scans"] >= TEL_PER_DAG:
        return jsonify({"geteld": False, "melding": f"Vandaag al {TEL_PER_DAG} scans van dit project meegeteld."}), 200
    if r is None:
        db().execute("INSERT INTO tel_projecten (project, eerste, eerste_op, laatste, laatste_op, scans, dag, dag_scans, bron) "
                     "VALUES (?,?,?,?,?,1,?,1,?)", (project, letter, t.isoformat(), letter, t.isoformat(), dag, bron))
    else:
        db().execute("UPDATE tel_projecten SET laatste = ?, laatste_op = ?, scans = scans + 1, "
                     "dag_scans = CASE WHEN dag = ? THEN dag_scans + 1 ELSE 1 END, dag = ? WHERE project = ?",
                     (letter, t.isoformat(), dag, dag, project))
    if bron == "zelf":
        db().execute("INSERT INTO tel_dagen (dag, zelf) VALUES (?, 1) ON CONFLICT(dag) DO UPDATE SET zelf = zelf + 1", (dag,))
    else:
        db().execute("INSERT INTO tel_dagen (dag, scans) VALUES (?, 1) ON CONFLICT(dag) DO UPDATE SET scans = scans + 1", (dag,))
    db().commit()
    return jsonify({"geteld": True, "melding": f"Meegeteld: score {letter}."}), 201


@app.post("/api/v1/telling/zelf")
def telling_zelf():
    """Zelfcontrole met een AI-agent (route A): telt mee met een geldig bewijsbestand en een ongebruikte sessiecode."""
    if (request.content_length or 0) > MAX_BEWIJS + 1024:
        return fout("Te groot.", 413)
    limiet()
    d = request.get_json(silent=True) or {}
    b, sleutel = d.get("bewijs"), str(d.get("project", ""))
    if not (len(sleutel) == 64 and all(ch in "0123456789abcdef" for ch in sleutel)):
        return fout("Verwacht: {bewijs, project} met project als sha256 (hex).")
    f, dag, eigen = controleer_bewijs(b, voor_telling=True)
    if f:
        return f
    letter = eigen["letter"]
    if not letter or letter not in LETTERS:
        return jsonify({"geteld": False, "melding": "Geen score, dus niets meegeteld."}), 200
    db().execute("UPDATE sessies SET geteld = 1 WHERE nonce = ?", (b["nonce"],))
    return tel(project_code("zelf:" + sleutel), letter, "zelf")


def statistiek() -> dict:
    """Voor checkmijn.ai/resultaten en de homepage."""
    c = db()
    github, zelf = c.execute("SELECT COALESCE(SUM(scans), 0), COALESCE(SUM(zelf), 0) FROM tel_dagen").fetchone()
    scans = github + zelf
    projecten = c.execute("SELECT COUNT(*) FROM tel_projecten").fetchone()[0]
    sinds = c.execute("SELECT MIN(dag) FROM tel_dagen").fetchone()[0]
    rijen = c.execute("SELECT eerste, laatste, COUNT(*) n FROM tel_projecten WHERE scans >= 2 GROUP BY eerste, laatste").fetchall()
    matrix = {(r["eerste"], r["laatste"]): r["n"] for r in rijen}
    herhaald = sum(matrix.values())
    beter = sum(n for (a, b), n in matrix.items() if LETTERS.index(b) < LETTERS.index(a))
    slechter = sum(n for (a, b), n in matrix.items() if LETTERS.index(b) > LETTERS.index(a))
    stappen = sum(n * (LETTERS.index(a) - LETTERS.index(b)) for (a, b), n in matrix.items() if LETTERS.index(b) < LETTERS.index(a))
    overgangen = sorted(((a, b, n) for (a, b), n in matrix.items() if a != b), key=lambda x: (-x[2], x[0], x[1]))
    eerste = {r["eerste"]: r["n"] for r in c.execute("SELECT eerste, COUNT(*) n FROM tel_projecten GROUP BY eerste")}
    laatste = {r["laatste"]: r["n"] for r in c.execute("SELECT laatste, COUNT(*) n FROM tel_projecten WHERE scans >= 2 GROUP BY laatste")}
    return {"scans": scans, "scans_github": github, "scans_zelf": zelf, "projecten": projecten, "sinds": sinds, "herhaald": herhaald, "beter": beter,
            "slechter": slechter, "gelijk": herhaald - beter - slechter, "matrix": matrix, "overgangen": overgangen,
            "gem_stappen": round(stappen / beter, 1) if beter else 0, "eerste": eerste, "laatste": laatste,
            "letters": LETTERS}


@app.get("/api/v1/statistiek")
def statistiek_api():
    s = statistiek()
    s["matrix"] = [{"van": a, "naar": b, "projecten": n} for (a, b), n in sorted(s["matrix"].items())]
    s["overgangen"] = [{"van": a, "naar": b, "projecten": n} for a, b, n in s["overgangen"]]
    return jsonify(s)


@app.get("/api/v1/rapport/<rid>")
def rapport_ophalen(rid):
    limiet()
    r = db().execute("SELECT aangemaakt, verloopt, iv, data, account FROM rapporten WHERE id = ?", (rid,)).fetchone()
    if not r or (r["account"] is None and r["verloopt"] < nu().isoformat()):
        return fout("Dit rapport bestaat niet (meer).", 404)
    return jsonify({"versie": 1, "alg": "A256GCM", "iv": r["iv"], "data": r["data"],
                    "aangemaakt": r["aangemaakt"][:10], "verloopt": r["verloopt"][:10]})


CSP_API = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; frame-ancestors 'none'"
CSP_SITE = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
            "font-src 'self'; frame-src 'self'; form-action 'self' mailto:; base-uri 'none'; object-src 'none'; "
            "frame-ancestors 'none'")
# Het versleutelde rapport heeft eigen stijlen in de pagina; het wordt in een sandbox-iframe getoond, zonder scripts.
CSP_RAPPORT = CSP_SITE.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'")


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), interest-cohort=()"
    if request.path.startswith(("/api/", "/score/")):
        resp.headers["Content-Security-Policy"] = CSP_API
    elif request.path.startswith(("/rapport/", "/voorbeeldrapport", "/nieuwsbrief/voorbeeld")):
        resp.headers["Content-Security-Policy"] = CSP_RAPPORT
    else:
        resp.headers["Content-Security-Policy"] = CSP_SITE
    if request.path.startswith(("/api/v1/score", "/score/")):
        resp.headers["Access-Control-Allow-Origin"] = "*"
    if request.path.startswith("/api/v1/rapport/"):
        resp.headers["Access-Control-Allow-Origin"] = SITE_ORIGIN
        resp.headers["Cache-Control"] = "private, no-store"
    return resp


# ------------------------------------------------------------------ website
import website as _site_mod  # noqa: E402  (platform/website.py)

app.register_blueprint(_site_mod.site)
_site_mod.BRON["tekst"] = lees_tekst


@app.errorhandler(404)
def niet_gevonden(e):
    if request.path.startswith("/api/"):
        return jsonify({"fout": "Niet gevonden."}), 404
    return render_template("site/404.html", titel="Pagina niet gevonden", beschrijving=""), 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("AISCAN_PORT", "5000")))
