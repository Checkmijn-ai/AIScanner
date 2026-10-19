"""API voor aiscan: sessiecodes, bewijs inleveren, scorepagina en badge.

Eindpunten
  GET  /api/v1/versie            manifest van de dagversie (latest.json)
  POST /api/v1/sessie            nieuwe sessiecode (nonce), 2 uur geldig, één keer bruikbaar
  POST /api/v1/resultaat         bewijs.json inleveren; geeft de scorepagina en de badge terug
  GET  /api/v1/score/<id>        de score als JSON
  GET  /score/<id>               publieke scorepagina
  GET  /score/<id>.svg           badge voor een README of website

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
STATUSSEN = {"Gehaald", "Bevinding", "Niet van toepassing", "Niet gescand"}
ERNST = {None, "Info", "Laag", "Middel", "Hoog", "Kritiek"}
KLEUR = {"A": "#1b7f3b", "B": "#4f9d2a", "C": "#97a91d", "D": "#c9a200", "E": "#e07f12", "F": "#d9480f", "G": "#b1161a"}

app = Flask(__name__, template_folder=str(ROOT / "platform" / "templates"))
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024  # een bewijs is klein; nooit code


# ------------------------------------------------------------------ opslag
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.executescript("""
            CREATE TABLE IF NOT EXISTS sessies (nonce TEXT PRIMARY KEY, aangemaakt TEXT, gebruikt INTEGER DEFAULT 0, ip TEXT);
            CREATE TABLE IF NOT EXISTS scores (id TEXT PRIMARY KEY, aangemaakt TEXT, geldig_tot TEXT, letter TEXT, soort TEXT,
                project TEXT, commit_hash TEXT, boom TEXT, dagversie TEXT, databank TEXT, bewijs TEXT);
        """)
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


@app.post("/api/v1/resultaat")
def resultaat():
    limiet()
    b = request.get_json(silent=True)
    if not isinstance(b, dict) or b.get("formaat") != "aiscan-bewijs/1":
        return fout("Geen geldig bewijsbestand (formaat aiscan-bewijs/1 verwacht).")
    for veld in ("nonce", "scanner", "project", "resultaten", "score"):
        if veld not in b:
            return fout(f"Veld '{veld}' ontbreekt.")

    # sessiecode
    row = db().execute("SELECT * FROM sessies WHERE nonce = ?", (str(b["nonce"]),)).fetchone()
    if not row:
        return fout("Onbekende sessiecode. Vraag een nieuwe via /api/v1/sessie.")
    if row["gebruikt"]:
        return fout("Deze sessiecode is al gebruikt. Elke scan heeft een nieuwe sessiecode nodig.")
    if nu() - dt.datetime.fromisoformat(row["aangemaakt"]) > NONCE_GELDIG:
        return fout("Sessiecode verlopen (2 uur). Vraag een nieuwe en scan opnieuw.")

    # scanner
    versies = lees("versies.json")
    sc = b["scanner"]
    dag = next((d for d, v in versies.items() if v["sha256"] == sc.get("sha256")), None)
    if not dag:
        return fout("Onbekende scanner: het controlegetal hoort bij geen gepubliceerde dagversie. Gebruik de instructie van vandaag.")
    if (nu().date() - dt.date.fromisoformat(dag)).days > MAX_LEEFTIJD:
        return fout(f"Dagversie {dag} is ouder dan {MAX_LEEFTIJD} dagen. Gebruik de instructie van vandaag.")
    v = versies[dag]
    if v.get("regelset") and sc.get("regelset") != v["regelset"]:
        return fout("De regelset in het bewijs hoort niet bij deze dagversie.")

    # resultaten
    res = b["resultaten"]
    if not isinstance(res, list) or sorted(r.get("id") for r in res) != sorted(v["checks"]):
        return fout("Het bewijs bevat niet precies de checks van deze dagversie.")
    for r in res:
        if r.get("status") not in STATUSSEN or r.get("zwaarste") not in ERNST or not isinstance(r.get("aantal"), int):
            return fout(f"Ongeldig resultaat voor {r.get('id')}.")
        if r["status"] == "Bevinding" and (r["aantal"] < 1 or r["zwaarste"] is None):
            return fout(f"Tegenstrijdig resultaat voor {r['id']}.")
        if r["status"] != "Bevinding" and r["zwaarste"] not in (None, "Info"):
            return fout(f"Tegenstrijdig resultaat voor {r['id']}.")

    # score zelf herberekenen
    niveau = int(b.get("niveau", 1))
    eigen = uit_bewijs(res, niveau)
    if eigen["letter"] != b["score"].get("letter"):
        return fout("De score in het bewijs klopt niet met de resultaten.")

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
        d = domeinen.setdefault(dname, {"Gehaald": 0, "Bevinding": 0, "Niet van toepassing": 0, "Niet gescand": 0})
        d[x["status"]] += 1
    return render_template("score.html", r=r, b=b, domeinen=sorted(domeinen.items()), kleur=KLEUR,
                           verlopen=nu().isoformat() > r["geldig_tot"], site=SITE)


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'"
    if request.path.startswith(("/api/v1/score", "/score/")):
        resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("AISCAN_PORT", "5000")))
