"""Nieuws voor checkmijn.ai/nieuws: RSS- en Atom-feeds ophalen, indelen in drie tabbladen en ontdubbelen.

Draait twee keer per dag via cron op de server (zie server/uitrol.sh):
    python /app/platform/nieuws.py            # ophalen en opslaan
    python /app/platform/nieuws.py --toon     # laat zien wat er nu in staat

Wat we tonen: titel, bron, datum en een korte inleiding uit de feed, met een link naar het volledige bericht.
Elk bericht staat in precies één tabblad. Berichten over hetzelfde nieuws (ook in een andere taal) worden
samengevoegd tot één bericht met "Ook bij: ...".
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import sys
import unicodedata
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

PAD = Path(os.environ.get("CHECKMIJN_NIEUWS", "/data/nieuws.json"))
BEWAAR_DAGEN = 21          # zo lang blijft een bericht staan
NIEUW_MAX_DAGEN = 7        # oudere berichten uit een feed nemen we niet meer op
SAMENVATTING_MAX = 220     # tekens van de inleiding
MAX_BYTES = 4_000_000
UA = "CheckMijn.AI-nieuws/1.0 (+https://checkmijn.ai/nieuws)"

TABS = {
    "ai-security": "AI-security",
    "cyber": "Cybersecurity",
    "ai": "AI-nieuws",
}
VOORRANG = {"ai-security": 0, "cyber": 1, "ai": 2}

# soort: waar de bron over gaat.
#   ai-security  alles naar AI-security (filter "sec": alleen als het over beveiliging gaat)
#   cyber        naar Cybersecurity, of naar AI-security als het over AI gaat
#   ai           naar AI-nieuws, of naar AI-security als het over beveiliging of incidenten gaat
#   tech         algemene techbron: alleen berichten over AI of beveiliging
BRONNEN = [
    # Cybersecurity
    {"naam": "Security.nl", "url": "https://www.security.nl/rss/headlines.xml", "taal": "nl", "soort": "cyber"},
    {"naam": "NCSC", "url": "https://feeds.ncsc.nl/nieuws.rss", "taal": "nl", "soort": "cyber"},
    {"naam": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "taal": "en", "soort": "cyber"},
    {"naam": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "taal": "en", "soort": "cyber"},
    {"naam": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "taal": "en", "soort": "cyber"},
    {"naam": "The Record", "url": "https://therecord.media/feed", "taal": "en", "soort": "cyber"},
    {"naam": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "taal": "en", "soort": "cyber"},
    # Algemene tech (alleen AI of beveiliging)
    {"naam": "Tweakers", "url": "https://tweakers.net/feeds/nieuws.xml", "taal": "nl", "soort": "tech"},
    {"naam": "NOS Tech", "url": "https://feeds.nos.nl/nosnieuwstech", "taal": "nl", "soort": "tech"},
    {"naam": "Techzine", "url": "https://www.techzine.nl/feed/", "taal": "nl", "soort": "tech"},
    {"naam": "Data News", "url": "https://datanews.knack.be/feed/", "taal": "nl", "soort": "tech"},
    # AI
    {"naam": "The Verge", "url": "https://www.theverge.com/rss/ai-artificial-intelligence/index.xml", "taal": "en", "soort": "ai"},
    {"naam": "TechCrunch", "url": "https://techcrunch.com/category/artificial-intelligence/feed/", "taal": "en", "soort": "ai"},
    {"naam": "MIT Technology Review", "url": "https://www.technologyreview.com/topic/artificial-intelligence/feed", "taal": "en", "soort": "ai"},
    {"naam": "The Register", "url": "https://www.theregister.com/software/ai_ml/headlines.atom", "taal": "en", "soort": "ai"},
    {"naam": "OpenAI", "url": "https://openai.com/news/rss.xml", "taal": "en", "soort": "ai"},
    {"naam": "Google DeepMind", "url": "https://deepmind.google/blog/rss.xml", "taal": "en", "soort": "ai"},
    {"naam": "Hugging Face", "url": "https://huggingface.co/blog/feed.xml", "taal": "en", "soort": "ai"},
    # AI-security
    {"naam": "SecurityWeek AI", "url": "https://www.securityweek.com/category/artificial-intelligence/feed/", "taal": "en", "soort": "ai-security"},
    {"naam": "Embrace The Red", "url": "https://embracethered.com/blog/index.xml", "taal": "en", "soort": "ai-security"},
    {"naam": "Simon Willison", "url": "https://simonwillison.net/atom/everything/", "taal": "en", "soort": "ai-security", "filter": "sec"},
]

# --- trefwoorden ---------------------------------------------------------------------------------------------
_AI_HOOFD = re.compile(r"\b(AI|A\.I\.|LLMs?|GenAI|GPT-?\d\w*|MCP)\b|\bAI-")
_AI = re.compile(
    r"\b(kunstmatige intelligentie|artificial intelligence|generatieve|generative|machine learning|chatbots?|chatgpt|"
    r"openai|anthropic|claude|gemini|copilot|mistral|llama|deepseek|grok|perplexity|agentic|ai[- ]agents?|"
    r"model context protocol|deepfakes?|taalmodel\w*|language models?|neural|vibe[- ]?cod\w*|cursor ide|lovable)\b", re.I)
_SEC = re.compile(
    r"(security|beveilig|hack|lek\b|lekken|datalek|kwetsba|vulnerab|exploit|cve-\d|malware|ransomware|phishing|"
    r"breach|aanval|attack|jailbreak|prompt[- ]?inje|backdoor|zero[- ]day|spyware|gestolen|stolen|leak|gelekt|"
    r"misbruik|abuse|fraud|oplicht|scam|cyber|incident|poison|exfiltr|rogue|deleted|wiped|gewist|verwijderd|"
    r"unsafe|safety|veiligheid|misalign|sabota|credential|wachtwoord|password|surveillance|privacy)", re.I)
# Voor AI-bronnen: alleen echte beveiligingswoorden in de titel (niet "attacking Nvidia" of "safety bill").
_SEC_AI = re.compile(
    r"(hack(ed|er|ers|ing|s)?\b|datalek|kwetsba|vulnerab|exploit|cve-\d|malware|ransomware|phishing|breach|"
    r"cyber|zero[- ]day|spyware|backdoor|lek\b|lekken|gelekt|leak|attackers?\b|aanvaller|prompt[- ]?inje|jailbreak|"
    r"exfiltr|rogue|stolen|gestolen|credentials|security flaw|beveiligingslek|data poisoning)", re.I)
_SEC_STERK = re.compile(
    r"(hack|datalek|kwetsba|vulnerab|exploit|cve-\d|malware|ransomware|phishing|breach|cyber|zero[- ]day|"
    r"spyware|backdoor|ddos|lek\b|lekken|gelekt|leak|aanval|attack|beveilig|security)", re.I)

# Wat een bericht betekent voor een app: verwijzing naar onze checks.
CHECK_REGELS = [
    (re.compile(r"prompt[- ]?inje|jailbreak", re.I), "H-01"),
    (re.compile(r"\bMCP\b|model context protocol", re.I), "H-21"),
    (re.compile(r"(ai[- ]?agent|agentic|coding agent|codeeragent).{0,80}(delet|wip|wist|verwijder|production|productie|rogue)|"
                r"(delet|wip|wist|verwijder).{0,80}(ai[- ]?agent|agentic)", re.I), "B-04"),
    (re.compile(r"api[- ]?(key|sleutel)|secrets?\b|credentials|tokens? (leak|gelekt|exposed)|hardcoded", re.I), "E-05"),
    (re.compile(r"\bnpm\b|pypi|supply[- ]chain|typosquat|slopsquat|malicious (package|librar)|kwaadaardige pakket", re.I), "B-06"),
    (re.compile(r"cve-\d|zero[- ]day|actively exploited|actief misbruikt|kwetsbaarheid|vulnerability", re.I), "F-01"),
    (re.compile(r"ransomware", re.I), "K-18"),
    (re.compile(r"supabase|firebase|row level security|\bRLS\b|exposed database|open databa", re.I), "W-13"),
    (re.compile(r"phishing|spoof|dmarc", re.I), "O-06"),
]


CHECK_NAMEN = {
    "H-01": "prompt injection", "H-04": "lekken via AI", "H-21": "tools en MCP", "B-04": "rechten van codeeragents", "E-05": "geheimen in code",
    "B-06": "verzonnen pakketten", "F-01": "bekende lekken", "K-18": "herstel na ransomware",
    "W-13": "rechten per rij in de databank", "O-06": "e-mail en domein",
}


# --- hulpjes -------------------------------------------------------------------------------------------------
class _Tekst(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.delen: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag in ("p", "br", "div", "li"):
            self.delen.append(" ")

    def handle_data(self, data):
        if not self._skip:
            self.delen.append(data)


def platte_tekst(s: str | None) -> str:
    if not s:
        return ""
    p = _Tekst()
    try:
        p.feed(s)
        p.close()
        t = "".join(p.delen)
    except Exception:
        t = re.sub(r"<[^>]+>", " ", s)
    t = html.unescape(t)
    return re.sub(r"\s+", " ", t).strip()


def titeltekst(s: str) -> str:
    """Titels: alleen opmaaktags weghalen; iets als "<router>" in een titel blijft staan."""
    s = re.sub(r"</?(b|i|em|strong|span|a|code|sup|sub)\b[^>]*>", "", s or "", flags=re.I)
    return re.sub(r"\s+", " ", html.unescape(s)).strip()


def kort(t: str, n: int = SAMENVATTING_MAX) -> str:
    t = re.sub(r"\s*(The post .* appeared first on .*|Lees verder.*|Read more.*|Continue reading.*)$", "", t)
    if len(t) <= n:
        return t
    t = t[:n].rsplit(" ", 1)[0].rstrip(",;:.-– ")
    return t + " …"


def nette_url(u: str) -> str:
    """Zelfde bericht, zelfde sleutel: zonder trackingparameters, www, schema en slash op het eind."""
    try:
        s = urlsplit(u.strip())
    except ValueError:
        return u
    q = [(k, v) for k, v in parse_qsl(s.query) if not k.lower().startswith(("utm_", "fbclid", "gclid", "mc_", "ref", "cmpid"))]
    host = s.netloc.lower().removeprefix("www.")
    return urlunsplit(("", host, s.path.rstrip("/"), urlencode(q), "")).lstrip("/")


def schone_link(u: str) -> str:
    try:
        s = urlsplit(u.strip())
    except ValueError:
        return ""
    if s.scheme not in ("http", "https"):
        return ""
    q = [(k, v) for k, v in parse_qsl(s.query) if not k.lower().startswith(("utm_", "fbclid", "gclid", "mc_"))]
    return urlunsplit((s.scheme, s.netloc, s.path, urlencode(q), ""))


STOP = set("""
de het een en of van in op te met voor door naar bij om aan als dat die dit deze is zijn was worden wordt werd niet ook
nog maar meer over uit tot dan wel geen kan na zo al hun haar hij zij we wij jij je ze er hoe wat wie waar nieuwe nieuw
the a an and or of in on to with for by from at as that this these is are was were be been not also more about into
than but can will new how what who why after over its their his her they we you your our has have had says said
""".split())


def woorden(titel: str) -> set[str]:
    t = unicodedata.normalize("NFKD", titel.lower())
    t = "".join(c for c in t if not unicodedata.combining(c))
    return {w for w in re.findall(r"[a-z0-9][a-z0-9\-]*", t) if (len(w) >= 3 or any(c.isdigit() for c in w)) and w not in STOP}


def namen(titel: str) -> set[str]:
    """Eigennamen, getallen en CVE-nummers: die zijn in elke taal gelijk."""
    delen = re.findall(r"[A-Za-zÀ-ÿ0-9][\w\-\.]*", titel)
    uit = set()
    for i, w in enumerate(delen):
        w = w.strip(".")
        if re.match(r"(?i)cve-\d{4}-\d+", w) or re.search(r"\d", w):
            uit.add(w.lower())
        elif i > 0 and w[:1].isupper() and len(w) > 2 and w.lower() not in STOP:
            uit.add(w.lower())
    return uit


def zelfde_nieuws(a: dict, b: dict) -> bool:
    try:
        da = datetime.fromisoformat(a["datum"])
        db = datetime.fromisoformat(b["datum"])
        if abs(da - db) > timedelta(hours=72):
            return False
    except Exception:
        pass
    cve_a = set(re.findall(r"(?i)cve-\d{4}-\d+", a["titel"]))
    if cve_a and cve_a & set(re.findall(r"(?i)cve-\d{4}-\d+", b["titel"])):
        return True
    wa, wb = woorden(a["titel"]), woorden(b["titel"])
    if wa and wb:
        gedeeld = len(wa & wb)
        jac = gedeeld / len(wa | wb)
        if (gedeeld >= 3 and jac >= 0.45) or (gedeeld >= 2 and jac >= 0.7):
            return True
    na, nb = namen(a["titel"]), namen(b["titel"])
    if len(na & nb) >= 3 and len(na & nb) / max(1, min(len(na), len(nb))) >= 0.6:
        return True
    return False


def indeling(bron: dict, titel: str, tekst: str) -> str | None:
    alles = f"{titel} {tekst}"
    is_ai = bool(_AI_HOOFD.search(titel) or _AI.search(titel) or _AI_HOOFD.search(tekst[:400]) or _AI.search(tekst[:400]))
    is_sec = bool(_SEC.search(alles))
    sterk = bool(_SEC_STERK.search(titel))
    soort = bron["soort"]
    if soort == "ai-security":
        # Een brede blog (filter "sec"): alleen de berichten over AI én beveiliging.
        if bron.get("filter") == "sec" and not (sterk or re.search(r"prompt[- ]?inje|jailbreak|exfiltr", alles, re.I)):
            return None
        return "ai-security"
    if soort == "cyber":
        return "ai-security" if (_AI_HOOFD.search(titel) or _AI.search(titel)) else "cyber"
    if soort == "ai":
        return "ai-security" if _SEC_AI.search(titel) else "ai"
    # tech: alleen wat in de titel over AI of beveiliging gaat
    ai_titel = bool(_AI_HOOFD.search(titel) or _AI.search(titel))
    if ai_titel and _SEC_AI.search(titel):
        return "ai-security"
    if ai_titel:
        return "ai"
    if _SEC_AI.search(titel):
        return "cyber"
    return None


# Berichten in een andere taal dan Nederlands of Engels (sommige feeds zijn gemengd) slaan we over.
_ANDERE_TAAL = re.compile(r"\b(pour|après|dans|avec|cette|une|les|des|sur|não|uma|para|com|em|por|após|sobre|und|nicht|"
                          r"für|mit|der|die|das|del|los|las|el|con|contra|nova|ação|pública|vaga|família)\b", re.I)


def andere_taal(titel: str) -> bool:
    letters = [c for c in titel if c.isalpha()]
    if letters and sum(1 for c in letters if ord(c) > 0x24F) / len(letters) > 0.3:  # ander schrift (Cyrillisch e.d.)
        return True
    return len(_ANDERE_TAAL.findall(titel)) >= 1 and not re.search(r"\b(the|and|of|het|een|van|voor|met)\b", titel, re.I)


def checks_bij(titel: str, tekst: str) -> list[str]:
    alles = f"{titel} {tekst}"
    uit = []
    for rx, cid in CHECK_REGELS:
        if rx.search(alles) and cid not in uit:
            uit.append(cid)
    return uit[:3]


# --- feeds lezen ---------------------------------------------------------------------------------------------
def _kind(el, *namen_):
    for c in el:
        if c.tag.split("}")[-1] in namen_:
            yield c


def _tekst(el, *namen_):
    for c in _kind(el, *namen_):
        if c.text and c.text.strip():
            return c.text.strip()
        if len(c):  # bv. xhtml-inhoud in Atom
            return ET.tostring(c, encoding="unicode", method="text").strip()
    return ""


def _datum(s: str) -> datetime | None:
    if not s:
        return None
    s = s.strip()
    try:
        d = parsedate_to_datetime(s)
    except Exception:
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def lees_feed(data: bytes) -> list[dict]:
    """RSS 2.0, RSS 1.0 (RDF) en Atom. Geeft {titel, url, tekst, datum}."""
    if b"<!ENTITY" in data[:5000]:
        raise ValueError("feed met DTD-entiteiten geweigerd")
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return lees_kapotte_feed(data)
    uit = []
    items = [el for el in root.iter() if el.tag.split("}")[-1] in ("item", "entry")]
    for it in items:
        titel = titeltekst(_tekst(it, "title"))
        link = ""
        for l in _kind(it, "link"):
            href = l.get("href")
            if href and l.get("rel", "alternate") == "alternate":
                link = href
                break
            if not href and l.text:
                link = l.text.strip()
                break
        if not link:
            g = _tekst(it, "guid", "id")
            if g.startswith("http"):
                link = g
        tekst = platte_tekst(_tekst(it, "description", "summary", "encoded", "content"))
        datum = _datum(_tekst(it, "pubDate", "published", "updated", "date", "issued"))
        if titel and link:
            uit.append({"titel": titel, "url": link, "tekst": tekst, "datum": datum})
    return uit


def lees_kapotte_feed(data: bytes) -> list[dict]:
    """Noodweg voor een RSS-feed met een XML-fout (bv. een losse tag in één bericht): per <item> met regexen."""
    t = data.decode("utf-8", "replace")

    def veld(blok, naam):
        m = re.search(rf"<{naam}[^>]*>(.*?)</{naam}>", blok, re.S | re.I)
        if not m:
            return ""
        v = m.group(1).strip()
        c = re.match(r"<!\[CDATA\[(.*)\]\]>$", v, re.S)
        return c.group(1) if c else v

    uit = []
    for blok in re.findall(r"<item[\s>](.*?)</item>", t, re.S | re.I):
        titel = titeltekst(html.unescape(veld(blok, "title")) if "CDATA" not in blok.split("</title>")[0] else veld(blok, "title"))
        link = html.unescape(veld(blok, "link") or veld(blok, "guid")).strip()
        if titel and link.startswith("http"):
            uit.append({"titel": titel, "url": link, "tekst": platte_tekst(veld(blok, "description")),
                        "datum": _datum(platte_tekst(veld(blok, "pubDate")))})
    if not uit:
        raise ValueError("feed niet leesbaar")
    return uit


def haal(bron: dict, staat: dict) -> tuple[list[dict], dict]:
    import requests

    st = dict(staat.get(bron["naam"], {}))
    kop = {"User-Agent": UA, "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.5"}
    if st.get("etag") and st.get("url") == bron["url"]:
        kop["If-None-Match"] = st["etag"]
    if st.get("lastmod") and st.get("url") == bron["url"]:
        kop["If-Modified-Since"] = st["lastmod"]
    st["url"] = bron["url"]
    st["laatst"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        r = requests.get(bron["url"], headers=kop, timeout=20, stream=True, allow_redirects=True)
        if r.status_code == 304:
            st.update(ok=True, fout="", nieuw=0)
            return [], st
        r.raise_for_status()
        data = b""
        for blok in r.iter_content(65536):
            data += blok
            if len(data) > MAX_BYTES:
                raise ValueError("feed te groot")
        items = lees_feed(data)
        st.update(ok=True, fout="", etag=r.headers.get("ETag", ""), lastmod=r.headers.get("Last-Modified", ""),
                  in_feed=len(items))
        return items, st
    except Exception as e:  # een kapotte bron mag de rest niet tegenhouden
        st.update(ok=False, fout=f"{type(e).__name__}: {str(e)[:160]}")
        return [], st


# --- opslag --------------------------------------------------------------------------------------------------
def laad(pad: Path = PAD) -> dict:
    try:
        return json.loads(pad.read_text(encoding="utf-8"))
    except Exception:
        return {"bijgewerkt": None, "items": [], "bronnen": {}}


def bewaar(d: dict, pad: Path = PAD) -> None:
    pad.parent.mkdir(parents=True, exist_ok=True)
    tmp = pad.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, pad)


def voeg_toe(d: dict, bron: dict, ruw: list[dict], nu: datetime) -> int:
    """Nieuwe berichten toevoegen; dubbels worden "Ook bij". Geeft het aantal nieuwe berichten."""
    bekend = set()
    for it in d["items"]:
        bekend.add(nette_url(it["url"]))
        for o in it.get("ook", []):
            bekend.add(nette_url(o["url"]))
    nieuw = 0
    grens = nu - timedelta(days=NIEUW_MAX_DAGEN)
    for r in ruw:
        if bron.get("max") and nieuw >= bron["max"]:
            break
        if andere_taal(r["titel"]):
            continue
        url = schone_link(r["url"])
        if not url or nette_url(url) in bekend:
            continue
        datum = r["datum"] or nu
        if datum > nu + timedelta(minutes=5):
            datum = nu
        if datum < grens:
            continue
        tab = indeling(bron, r["titel"], r["tekst"])
        if not tab:
            continue
        kandidaat = {"titel": r["titel"], "datum": datum.isoformat(timespec="seconds")}
        dubbel = next((it for it in d["items"] if zelfde_nieuws(kandidaat, it)), None)
        if dubbel:
            if bron["naam"] != dubbel["bron"] and all(o["bron"] != bron["naam"] for o in dubbel.get("ook", [])):
                dubbel.setdefault("ook", []).append({"bron": bron["naam"], "url": url, "taal": bron["taal"]})
            if VOORRANG[tab] < VOORRANG[dubbel["tab"]]:
                dubbel["tab"] = tab
            for c in checks_bij(r["titel"], r["tekst"]):
                if c not in dubbel.setdefault("checks", []) and len(dubbel["checks"]) < 3:
                    dubbel["checks"].append(c)
            bekend.add(nette_url(url))
            continue
        d["items"].append({
            "id": hashlib.sha256(nette_url(url).encode()).hexdigest()[:12],
            "titel": r["titel"],
            "url": url,
            "bron": bron["naam"],
            "taal": bron["taal"],
            "datum": datum.isoformat(timespec="seconds"),
            "gezien": nu.isoformat(timespec="seconds"),
            "samenvatting": kort(r["tekst"]) if r["tekst"] and r["tekst"] != r["titel"] else "",
            "tab": tab,
            "checks": checks_bij(r["titel"], r["tekst"]),
            "ook": [],
        })
        bekend.add(nette_url(url))
        nieuw += 1
    return nieuw


def ophalen(pad: Path = PAD, bronnen: list[dict] = BRONNEN, haler=haal) -> dict:
    nu = datetime.now(timezone.utc)
    d = laad(pad)
    d.setdefault("bronnen", {})
    grens = nu - timedelta(days=BEWAAR_DAGEN)
    d["items"] = [it for it in d.get("items", []) if datetime.fromisoformat(it["datum"]) >= grens]
    # Regels kunnen veranderen: bestaande berichten opnieuw indelen (en weglaten wat er niet meer bij hoort).
    per_naam = {b["naam"]: b for b in bronnen}
    bewaard = []
    for it in d["items"]:
        b = per_naam.get(it["bron"])
        if b is None or andere_taal(it["titel"]):
            continue
        tab = indeling(b, it["titel"], it.get("samenvatting", ""))
        if tab is None:
            continue
        if not any(o["bron"] in per_naam and VOORRANG[tab] > VOORRANG[it["tab"]] for o in it.get("ook", [])):
            it["tab"] = tab
        bewaard.append(it)
    d["items"] = bewaard
    with ThreadPoolExecutor(max_workers=8) as pool:
        resultaten = list(pool.map(lambda b: haler(b, d["bronnen"]), bronnen))
    # Vaste volgorde (de lijst hierboven), zodat dezelfde feeds altijd hetzelfde resultaat geven.
    for bron, (ruw, st) in zip(bronnen, resultaten):
        st["nieuw"] = voeg_toe(d, bron, ruw, nu) if ruw else 0
        d["bronnen"][bron["naam"]] = st
    namen_nu = {b["naam"] for b in bronnen}
    d["bronnen"] = {k: v for k, v in d["bronnen"].items() if k in namen_nu}
    d["items"].sort(key=lambda it: it["datum"], reverse=True)
    d["bijgewerkt"] = nu.isoformat(timespec="seconds")
    bewaar(d, pad)
    return d


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--toon", action="store_true", help="niets ophalen, alleen tonen wat er is")
    ap.add_argument("--pad", type=Path, default=PAD)
    a = ap.parse_args(argv)
    d = laad(a.pad) if a.toon else ophalen(a.pad)
    tel = {t: sum(1 for i in d["items"] if i["tab"] == t) for t in TABS}
    print(f"bijgewerkt {d.get('bijgewerkt')}: " + ", ".join(f"{TABS[t]} {n}" for t, n in tel.items()))
    for naam, st in d.get("bronnen", {}).items():
        print(f"  {'ok ' if st.get('ok') else 'FOUT'} {naam:24} nieuw {st.get('nieuw', 0):3}  {st.get('fout', '')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
