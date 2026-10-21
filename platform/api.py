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
Daarom is elke score via deze route een "Zelfcontrole". Een geverifieerde scan komt via een attestation van
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
from aiscan.score import uit_bewijs  # noqa: E402

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
        for tabel, kolom in (("sessies", "geteld INTEGER DEFAULT 0"), ("tel_projecten", "bron TEXT DEFAULT 'github'"),
                             ("tel_dagen", "zelf INTEGER DEFAULT 0")):
            try:
                g.db.execute(f"ALTER TABLE {tabel} ADD COLUMN {kolom}")
            except sqlite3.OperationalError:
                pass  # bestaat al
    return g.db


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
                       "checkmijn.yml": "text/plain; charset=utf-8"}


def _dagversie_bestand(naam):
    def view():
        return Response(lees_tekst(naam), mimetype=DAGVERSIE_BESTANDEN[naam],
                        headers={"Access-Control-Allow-Origin": "*", "Cache-Control": "public, max-age=300"})
    view.__name__ = "dagversie_" + naam.replace(".", "_").replace("-", "_")
    return view


for _naam in DAGVERSIE_BESTANDEN:
    app.add_url_rule(f"/{_naam}", view_func=_dagversie_bestand(_naam))


# ------------------------------------------------------------------ API
@app.get("/api/v1/versie")
def versie():
    return jsonify(lees("latest.json"))


@app.post("/api/v1/sessie")
def sessie():
    ip = limiet()
    nonce = secrets.token_urlsafe(18)
    db().execute("INSERT INTO sessies (nonce, aangemaakt, ip) VALUES (?, ?, ?)", (nonce, nu().isoformat(), ip))
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
    eigen = uit_bewijs(res, int(b.get("niveau", 1)))
    if eigen["letter"] != b["score"].get("letter"):
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
    soort = "Zelfcontrole"
    geldig = nu() + SCORE_GELDIG
    pr = b["project"]
    db().execute("UPDATE sessies SET gebruikt = 1 WHERE nonce = ?", (b["nonce"],))
    db().execute("INSERT INTO scores VALUES (?,?,?,?,?,?,?,?,?,?,?)",
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


@app.get("/api/v1/score/<sid>")
def score_json(sid):
    r = _score(sid)
    b = json.loads(r["bewijs"])
    return jsonify({"id": r["id"], "score": r["letter"], "soort": r["soort"], "project": r["project"],
                    "commit": r["commit_hash"], "dagversie": r["dagversie"], "databank": r["databank"],
                    "aangemaakt": r["aangemaakt"], "geldig_tot": r["geldig_tot"], "verlopen": nu().isoformat() > r["geldig_tot"],
                    "ernst": b.get("ernst"), "resultaten": b.get("resultaten")})


@app.get("/score/<sid>.svg")
def badge(sid):
    r = _score(sid)
    verlopen = nu().isoformat() > r["geldig_tot"]
    letter = r["letter"] or "–"
    rechts = f"{letter} · {'verlopen' if verlopen else r['soort'].lower()}"
    kleur = "#8a94a6" if verlopen or not r["letter"] else KLEUR[letter]
    wl, wr = 74, 8 + 7 * len(rechts)
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{wl + wr}" height="22" role="img" aria-label="Scanscore {html.escape(rechts)}">
<title>Scanscore {html.escape(rechts)} · {html.escape(r['project'])} · {r['aangemaakt'][:10]}</title>
<rect width="{wl}" height="22" rx="3" fill="#15203a"/><rect x="{wl}" width="{wr}" height="22" rx="3" fill="{kleur}"/>
<rect x="{wl - 3}" width="6" height="22" fill="{kleur}"/>
<g font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" fill="#fff">
<text x="9" y="15">Scanscore</text><text x="{wl + 6}" y="15" font-weight="bold">{html.escape(rechts)}</text></g></svg>'''
    return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control": "max-age=3600"})


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
    return render_template("score.html", r=r, b=b, domeinen=sorted(domeinen.items()), kleur=KLEUR,
                           verlopen=nu().isoformat() > r["geldig_tot"], site=SITE)


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
    letter = str((request.get_json(silent=True) or {}).get("letter", ""))
    if len(letter) != 1 or letter not in LETTERS:
        return fout("Verwacht: {letter: A–G}.")
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
    kolom = "zelf" if bron == "zelf" else "scans"
    db().execute(f"INSERT INTO tel_dagen (dag, {kolom}) VALUES (?, 1) ON CONFLICT(dag) DO UPDATE SET {kolom} = {kolom} + 1", (dag,))
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
