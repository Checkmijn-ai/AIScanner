"""Controles op de draaiende site of app (alleen met --url en schriftelijke toestemming van de eigenaar).

D-12 aanvalsoppervlak · E-08 headers en CORS · O-04 cookies vóór toestemming · O-05 site veilig ·
O-06 e-mail en domein · Y-01 TLS · Y-02 onversleutelde protocollen · Y-04 verouderde protocollen.
Dit is een externe kwetsbaarheidsscan, geen pentest: er wordt niets misbruikt.
"""
from __future__ import annotations

import datetime as dt
import random
import re
import socket
import ssl
import struct
from urllib.parse import urlparse

from . import check
from ..core import Finding, Result, snippet

PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP", 389: "LDAP", 445: "SMB", 1433: "SQL Server",
         1521: "Oracle", 1883: "MQTT", 2375: "Docker API", 3000: "ontwikkelserver", 3306: "MySQL", 3389: "RDP", 5000: "ontwikkelserver",
         5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC", 6379: "Redis", 8000: "ontwikkelserver", 8080: "HTTP-alt", 8443: "HTTPS-alt",
         9000: "beheer", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"}
CRITICAL_PORTS = {2375, 3306, 5432, 6379, 9200, 11211, 27017, 1433, 1521, 5900, 23, 445, 3389}
TRACK_COOKIES = re.compile(r"^(_ga|_gid|_gat|_fbp|_fbc|_hj|_clck|_clsk|ajs_|mp_|_gcl|_uet|_tt_|li_|IDE|__hs|hubspot|_pin)", re.I)


def _need(proj, cid):
    r = Result(cid)
    if not proj.url:
        r.status, r.reden = "Niet gescand", "Geen URL opgegeven. Start met --url en schriftelijke toestemming van de eigenaar."
    elif proj.offline:
        r.status, r.reden = "Niet gescand", "Offline gestart; de live site is niet bezocht."
    return r


def _ctx(proj):
    if hasattr(proj, "_live"):
        return proj._live
    import requests
    u = urlparse(proj.url if "://" in proj.url else "https://" + proj.url)
    host = u.hostname
    live = {"host": host, "url": f"https://{host}{u.path or '/'}", "error": None}
    try:
        resp = requests.get(live["url"], timeout=15, allow_redirects=True, headers={"User-Agent": "aiscan/0.1 (geautoriseerde scan)"})
        live["resp"] = resp
        live["first"] = resp.history[0] if resp.history else resp
        live["set_cookies"] = []
        for h in (resp.history + [resp]):
            live["set_cookies"] += h.raw.headers.getlist("Set-Cookie") if hasattr(h.raw, "headers") else []
    except requests.exceptions.SSLError:
        # certificaatprobleem: Y-01 meldt het; de andere controles gaan verder zonder certificaatcontrole
        import urllib3
        urllib3.disable_warnings()
        try:
            resp = requests.get(live["url"], timeout=15, allow_redirects=True, verify=False,
                                headers={"User-Agent": "aiscan/0.1 (geautoriseerde scan)"})
            live["resp"], live["first"], live["insecure"] = resp, (resp.history[0] if resp.history else resp), True
            live["set_cookies"] = []
            for h in (resp.history + [resp]):
                live["set_cookies"] += h.raw.headers.getlist("Set-Cookie") if hasattr(h.raw, "headers") else []
        except Exception as e:
            live["error"] = f"Site niet bereikbaar: {type(e).__name__}"
    except Exception as e:
        live["error"] = f"Site niet bereikbaar: {type(e).__name__}"
    proj._live = live
    return live


def _tcp(host, port, timeout=2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(2)
            try:
                return s.recv(128)
            except Exception:
                return b""
    except Exception:
        return None


def _ports(proj):
    live = _ctx(proj)
    if "ports" not in live:
        live["ports"] = {p: _tcp(live["host"], p) for p in PORTS}
    return live["ports"]


# ---------------------------------------------------------------- D-12
@check("D-12")
def attack_surface(proj, meta):
    r = _need(proj, "D-12")
    if r.status != "Geen bevinding":
        return r
    live = _ctx(proj)
    open_ports = {p: b for p, b in _ports(proj).items() if b is not None}
    for p, banner in sorted(open_ports.items()):
        if p in (80, 443):
            continue
        sev = "Hoog" if p in CRITICAL_PORTS else "Middel"
        r.add(Finding("D-12", sev, f"Poort {p} ({PORTS[p]}) is publiek bereikbaar", f"{live['host']}:{p}",
                      bewijs=snippet(banner.decode('latin-1', 'replace')) if banner else "", bevestigen=sev != "Hoog"))
    r.info.append(f"{len(PORTS)} veelgebruikte poorten nagekeken op {live['host']}; open: "
                  + (", ".join(str(p) for p in sorted(open_ports)) or "geen"))
    r.info.append("Subdomeinen worden in deze versie niet opgespoord; geef ze apart op.")
    return r


# ---------------------------------------------------------------- E-08
HEADERS = [("strict-transport-security", "Hoog", "HSTS ontbreekt"),
           ("content-security-policy", "Middel", "Content Security Policy ontbreekt"),
           ("x-content-type-options", "Laag", "X-Content-Type-Options ontbreekt"),
           ("referrer-policy", "Laag", "Referrer-Policy ontbreekt")]


@check("E-08")
def headers(proj, meta):
    r = _need(proj, "E-08")
    if r.status != "Geen bevinding":
        return r
    live = _ctx(proj)
    if live["error"]:
        r.status, r.reden = "Niet gescand", live["error"]
        return r
    import requests
    h = {k.lower(): v for k, v in live["resp"].headers.items()}
    for name, sev, title in HEADERS:
        if name not in h:
            r.add(Finding("E-08", sev, title, live["resp"].url))
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        r.add(Finding("E-08", "Middel", "Geen bescherming tegen clickjacking (X-Frame-Options of frame-ancestors)", live["resp"].url))
    csp = h.get("content-security-policy", "")
    if csp and re.search(r"'unsafe-inline'|'unsafe-eval'|script-src[^;]*\*", csp):
        r.add(Finding("E-08", "Laag", "Content Security Policy laat inline of eval toe", live["resp"].url, bewijs=snippet(csp)))
    try:
        evil = "https://aiscan-cors-test.example"
        cr = requests.get(live["resp"].url, headers={"Origin": evil}, timeout=10, verify=not live.get("insecure"))
        acao, acac = cr.headers.get("Access-Control-Allow-Origin"), cr.headers.get("Access-Control-Allow-Credentials")
        if acao == evil and acac == "true":
            r.add(Finding("E-08", "Hoog", "CORS laat elke herkomst toe, met cookies", live["resp"].url, bewijs=f"Access-Control-Allow-Origin: {acao}"))
        elif acao == evil:
            r.add(Finding("E-08", "Middel", "CORS weerspiegelt elke herkomst", live["resp"].url, bewijs=f"Access-Control-Allow-Origin: {acao}"))
    except Exception:
        pass
    for k in ("server", "x-powered-by"):
        if k in h and re.search(r"\d", h[k]):
            r.add(Finding("E-08", "Laag", f"Header {k} toont de softwareversie", live["resp"].url, bewijs=f"{k}: {h[k]}"))
    return r


# ---------------------------------------------------------------- Y-01
WEAK_CIPHERS = "RC4:3DES:DES:NULL:EXPORT:aNULL:eNULL:MD5"


def _tls_try(host, **kw):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        if "max" in kw:
            ctx.minimum_version = kw["max"]
            ctx.maximum_version = kw["max"]
        if "ciphers" in kw:
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2  # TLS 1.3 heeft vaste, sterke suites
            ctx.set_ciphers(kw["ciphers"])
    except (ValueError, ssl.SSLError):
        return None  # deze OpenSSL kan het niet testen
    try:
        with socket.create_connection((host, 443), timeout=5) as s, ctx.wrap_socket(s, server_hostname=host) as t:
            return t.version()
    except Exception:
        return False


@check("Y-01")
def tls(proj, meta):
    r = _need(proj, "Y-01")
    if r.status != "Geen bevinding":
        return r
    host = _ctx(proj)["host"]
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=8) as s, ctx.wrap_socket(s, server_hostname=host) as t:
            cert = t.getpeercert()
            r.info.append(f"Verbinding met {t.version()} en {t.cipher()[0]}.")
            end = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days = (end - dt.datetime.utcnow()).days
            if days < 0:
                r.add(Finding("Y-01", "Kritiek", "Certificaat verlopen", host, bewijs=cert["notAfter"]))
            elif days < 21:
                r.add(Finding("Y-01", "Middel", f"Certificaat verloopt binnen {days} dagen", host, bewijs=cert["notAfter"]))
    except ssl.SSLCertVerificationError as e:
        r.add(Finding("Y-01", "Hoog", "Certificaat niet geldig of keten onvolledig", host, bewijs=snippet(str(e))))
    except Exception as e:
        r.status, r.reden = "Niet gescand", f"Geen TLS-verbinding met {host}:443 ({type(e).__name__})."
        return r
    for ver, name in ((ssl.TLSVersion.TLSv1, "TLS 1.0"), (ssl.TLSVersion.TLSv1_1, "TLS 1.1")):
        res = _tls_try(host, max=ver)
        if res:
            r.add(Finding("Y-01", meta["ernst"], f"{name} wordt nog aanvaard", host))
        elif res is None:
            r.info.append(f"{name} kon met deze OpenSSL-versie niet getest worden.")
    weak = _tls_try(host, ciphers=WEAK_CIPHERS)
    if weak is None:
        r.info.append("Zwakke cipher suites konden met deze OpenSSL-versie niet getest worden.")
    if weak:
        r.add(Finding("Y-01", meta["ernst"], "Zwakke cipher suites worden aanvaard", host, bewijs=WEAK_CIPHERS))
    live = _ctx(proj)
    if not live.get("error") and "strict-transport-security" not in {k.lower() for k in live["resp"].headers}:
        r.add(Finding("Y-01", "Middel", "Geen HSTS", host))
    return r


# ---------------------------------------------------------------- Y-02
@check("Y-02")
def plaintext(proj, meta):
    r = _need(proj, "Y-02")
    if r.status != "Geen bevinding":
        return r
    import requests
    host = _ctx(proj)["host"]
    try:
        resp = requests.get(f"http://{host}/", timeout=10, allow_redirects=False)
        loc = resp.headers.get("Location", "")
        if resp.status_code not in (301, 302, 307, 308) or not loc.startswith("https://"):
            r.add(Finding("Y-02", meta["ernst"], "HTTP stuurt niet door naar HTTPS", f"http://{host}/", bewijs=f"HTTP {resp.status_code}"))
    except Exception:
        r.info.append("Poort 80 niet bereikbaar (geen HTTP).")
    for p in (21, 23, 389, 1883, 110, 143):
        if _ports(proj).get(p) is not None:
            r.add(Finding("Y-02", meta["ernst"], f"Onversleuteld protocol bereikbaar: {PORTS[p]} (poort {p})", f"{host}:{p}"))
    return r


# ---------------------------------------------------------------- Y-04
@check("Y-04")
def legacy(proj, meta):
    r = _need(proj, "Y-04")
    if r.status != "Geen bevinding":
        return r
    host = _ctx(proj)["host"]
    ports = _ports(proj)
    b = ports.get(22)
    if b is not None:
        banner = b.decode("latin-1", "replace").strip()
        if banner.startswith("SSH-1."):
            r.add(Finding("Y-04", "Kritiek", "SSH versie 1 wordt aanvaard", f"{host}:22", bewijs=banner))
        else:
            r.info.append(f"SSH bereikbaar: {banner or 'geen banner'}; algoritmen en sleutels vragen een SSH-audit (niveau 2).")
    if ports.get(3389) is not None:
        r.add(Finding("Y-04", meta["ernst"], "RDP is publiek bereikbaar", f"{host}:3389"))
    if ports.get(445) is not None:
        r.add(Finding("Y-04", meta["ernst"], "SMB is publiek bereikbaar (SMBv1 niet uit te sluiten)", f"{host}:445"))
    return r


# ---------------------------------------------------------------- O-04
@check("O-04")
def cookies_before_consent(proj, meta):
    r = _need(proj, "O-04")
    if r.status != "Geen bevinding":
        return r
    live = _ctx(proj)
    if live["error"]:
        r.status, r.reden = "Niet gescand", live["error"]
        return r
    names = [c.split("=", 1)[0].strip() for c in live.get("set_cookies", [])]
    for n in names:
        if TRACK_COOKIES.match(n):
            r.add(Finding("O-04", meta["ernst"], f"Trackingcookie '{n}' geplaatst vóór toestemming", live["resp"].url))
    html = live["resp"].text[:500000]
    from .code import TRACKERS, CONSENT
    if TRACKERS.search(html) and not CONSENT.search(html):
        r.add(Finding("O-04", meta["ernst"], "Trackingscripts op de pagina zonder zichtbaar toestemmingsbeheer", live["resp"].url,
                      bevestigen=True))
    r.info.append(f"Cookies van de server bij het eerste bezoek: {', '.join(names) or 'geen'}. "
                  "Cookies die JavaScript in de browser plaatst, zijn zo niet te zien; een controle met een echte browser volgt in een latere versie.")
    return r


# ---------------------------------------------------------------- O-05
PROBES = [("/.git/HEAD", re.compile(r"^ref: refs/"), "Kritiek", "Git-map publiek leesbaar"),
          ("/.env", re.compile(r"^[A-Z_]+=", re.M), "Kritiek", ".env-bestand publiek leesbaar"),
          ("/phpmyadmin/", re.compile(r"phpMyAdmin", re.I), "Hoog", "phpMyAdmin publiek bereikbaar"),
          ("/server-status", re.compile(r"Apache Server Status", re.I), "Middel", "Serverstatus publiek bereikbaar"),
          ("/wp-admin/", re.compile(r"wp-login|WordPress", re.I), "Laag", "WordPress-beheer publiek bereikbaar"),
          ("/admin/", re.compile(r"(login|admin)", re.I), "Laag", "Beheerpagina publiek bereikbaar")]


@check("O-05")
def site_safe(proj, meta):
    r = _need(proj, "O-05")
    if r.status != "Geen bevinding":
        return r
    import requests
    live = _ctx(proj)
    if live["error"]:
        r.status, r.reden = "Niet gescand", live["error"]
        return r
    base = f"https://{live['host']}"
    for path, rx, sev, title in PROBES:
        try:
            resp = requests.get(base + path, timeout=8, allow_redirects=False, verify=not live.get("insecure"))
            if resp.status_code == 200 and rx.search(resp.text[:5000]):
                r.add(Finding("O-05", sev, title, base + path, bevestigen=sev in ("Laag", "Middel")))
        except Exception:
            pass
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', live["resp"].text[:200000], re.I)
    if m:
        r.add(Finding("O-05", "Laag", f"De site toont het CMS en de versie: {m.group(1)}", live["resp"].url, bevestigen=True,
                      bewijs="Controleer of dit de laatste versie is, met bijgewerkte plugins."))
    r.info.append("TLS en headers: zie Y-01 en E-08.")
    return r


# ---------------------------------------------------------------- O-06 (kleine DNS-client, geen extra pakketten)
def _resolver():
    try:
        for line in open("/etc/resolv.conf"):
            if line.startswith("nameserver"):
                return line.split()[1]
    except OSError:
        pass
    return "1.1.1.1"


def dns(name, qtype):
    types = {"TXT": 16, "MX": 15, "CNAME": 5, "DS": 43, "A": 1}
    tid = random.randint(0, 65535)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for part in name.rstrip(".").split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00" + struct.pack(">HH", types[qtype], 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    try:
        s.sendto(q, (_resolver(), 53))
        data = s.recv(4096)
    finally:
        s.close()
    rcode = data[3] & 0x0F
    an = struct.unpack(">H", data[6:8])[0]
    i = len(q)
    out = []

    def skip_name(i):
        while True:
            ln = data[i]
            if ln == 0:
                return i + 1
            if ln & 0xC0 == 0xC0:
                return i + 2
            i += ln + 1
    for _ in range(an):
        i = skip_name(i)
        t, _, _, rdlen = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        rd = data[i:i + rdlen]
        i += rdlen
        if t == 16:
            txt, j = b"", 0
            while j < len(rd):
                ln = rd[j]
                txt += rd[j + 1:j + 1 + ln]
                j += ln + 1
            out.append(txt.decode("utf-8", "replace"))
        elif t == types[qtype]:
            out.append(rd)
    return rcode, out


@check("O-06")
def mail_domain(proj, meta):
    r = _need(proj, "O-06")
    if r.status != "Geen bevinding":
        return r
    host = _ctx(proj)["host"]
    domain = ".".join(host.split(".")[-2:]) if not host.endswith((".co.uk", ".com.au")) else ".".join(host.split(".")[-3:])
    try:
        _, txt = dns(domain, "TXT")
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        if not spf:
            r.add(Finding("O-06", meta["ernst"], "Geen SPF-record", domain))
        elif re.search(r"[+?]all\b", spf[0]):
            r.add(Finding("O-06", meta["ernst"], "SPF laat elke afzender toe", domain, bewijs=spf[0]))
        _, dm = dns("_dmarc." + domain, "TXT")
        dmarc = [t for t in dm if t.lower().startswith("v=dmarc1")]
        if not dmarc:
            r.add(Finding("O-06", meta["ernst"], "Geen DMARC-record", domain))
        elif re.search(r"\bp=none\b", dmarc[0], re.I):
            r.add(Finding("O-06", "Laag", "DMARC staat op p=none: vervalste e-mail wordt niet tegengehouden", domain, bewijs=dmarc[0]))
        found = []
        for sel in ("default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2", "mxvault"):
            _, d = dns(f"{sel}._domainkey.{domain}", "TXT")
            if any("p=" in t for t in d):
                found.append(sel)
        r.info.append("DKIM gevonden voor selector(s): " + (", ".join(found) if found else
                      "geen van de gangbare selectors; de klant bevestigt de selector"))
        _, ds = dns(domain, "DS")
        r.info.append("DNSSEC: " + ("aan" if ds else "niet aan (aanbevolen waar mogelijk)"))
    except Exception as e:
        r.status, r.reden = "Niet gescand", f"DNS niet bereikbaar ({type(e).__name__})."
    r.info.append("Overneembare subdomeinen worden in deze versie niet opgespoord.")
    return r
