"""Nieuws: feeds lezen, indelen in drie tabbladen, dubbels samenvoegen (ook NL/EN), en de pagina tonen."""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
tmp = Path(tempfile.mkdtemp())
os.environ["CHECKMIJN_NIEUWS"] = str(tmp / "nieuws.json")
(tmp / "scan.md").write_text("# test\n")
os.environ.update({"AISCAN_DB": str(tmp / "t.db"), "AISCAN_PUBLIC": str(tmp)})
sys.path.insert(0, str(ROOT / "platform"))
import nieuws as nw  # noqa: E402

nu = datetime.now(timezone.utc)
uur = lambda h: format_datetime(nu - timedelta(hours=h))  # noqa: E731

RSS_NL = f"""<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>Albert Heijn getroffen door datalek bij leverancier Bakkerij Systems</title>
<link>https://www.security.nl/posting/1/ah?utm_source=rss</link><pubDate>{uur(3)}</pubDate>
<description>&lt;p&gt;Klantgegevens van &lt;b&gt;Albert Heijn&lt;/b&gt; zijn gelekt.&lt;/p&gt;</description></item>
<item><title>AI-agent wist productiedatabase van startup</title><link>https://www.security.nl/posting/2</link>
<pubDate>{uur(5)}</pubDate><description>De codeeragent verwijderde de database.</description></item>
<item><title>Oud bericht</title><link>https://www.security.nl/posting/0</link><pubDate>{uur(24 * 30)}</pubDate></item>
</channel></rss>""".encode()

RSS_EN = f"""<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>Albert Heijn data breach linked to Bakkerij Systems supplier hack</title>
<link>https://www.bleepingcomputer.com/news/ah/</link><pubDate>{uur(2)}</pubDate><description>Dutch retailer.</description></item>
<item><title>Critical CVE-2026-12345 in Fortinet actively exploited</title><link>https://www.bleepingcomputer.com/news/forti/</link>
<pubDate>{uur(1)}</pubDate><description>Patch now.</description></item>
</channel></rss>""".encode()

ATOM_AI = f"""<?xml version="1.0" encoding="utf-8"?><feed xmlns="http://www.w3.org/2005/Atom"><title>t</title>
<entry><title>OpenAI releases a new reasoning model</title><link rel="alternate" href="https://example.org/a"/>
<updated>{(nu - timedelta(hours=4)).isoformat()}</updated><summary>Faster and cheaper.</summary></entry>
<entry><title>New prompt injection attack hijacks ChatGPT agents</title><link href="https://example.org/b"/>
<updated>{(nu - timedelta(hours=6)).isoformat()}</updated><summary>Researchers show exfiltration via MCP tools.</summary></entry>
<entry><title>Fortinet patches CVE-2026-12345 after attacks</title><link href="https://example.org/c"/>
<updated>{(nu - timedelta(hours=1)).isoformat()}</updated></entry>
</feed>""".encode()

BRONNEN = [
    {"naam": "Security.nl", "url": "https://x/nl", "taal": "nl", "soort": "cyber"},
    {"naam": "BleepingComputer", "url": "https://x/en", "taal": "en", "soort": "cyber"},
    {"naam": "Voorbeeld AI", "url": "https://x/ai", "taal": "en", "soort": "ai"},
    {"naam": "Kapot", "url": "https://x/kapot", "taal": "en", "soort": "ai"},
]
FEEDS = {"https://x/nl": RSS_NL, "https://x/en": RSS_EN, "https://x/ai": ATOM_AI}


def nep_haal(bron, staat):
    if bron["url"] not in FEEDS:
        return [], {"ok": False, "fout": "ConnectionError: test"}
    return nw.lees_feed(FEEDS[bron["url"]]), {"ok": True, "fout": ""}


d = nw.ophalen(nw.PAD, BRONNEN, nep_haal)
items = d["items"]
titels = {i["titel"]: i for i in items}

# 1. oude berichten niet, trackingparameters weg, HTML uit de inleiding
assert "Oud bericht" not in titels
ah = titels["Albert Heijn getroffen door datalek bij leverancier Bakkerij Systems"]
assert ah["url"] == "https://www.security.nl/posting/1/ah", ah["url"]
assert ah["samenvatting"] == "Klantgegevens van Albert Heijn zijn gelekt.", ah["samenvatting"]

# 2. NL en EN over hetzelfde nieuws: één bericht met "Ook bij"
assert "Albert Heijn data breach linked to Bakkerij Systems supplier hack" not in titels
assert [o["bron"] for o in ah["ook"]] == ["BleepingComputer"], ah["ook"]
assert ah["tab"] == "cyber"

# 3. Zelfde CVE in twee bronnen: één bericht
forti = [i for i in items if "CVE-2026-12345" in i["titel"]]
assert len(forti) == 1 and len(forti[0]["ook"]) == 1, forti
assert "F-01" in forti[0]["checks"]

# 4. Indeling: AI in een cyberbron → AI-security; beveiliging in een AI-bron → AI-security; anders AI-nieuws
assert titels["AI-agent wist productiedatabase van startup"]["tab"] == "ai-security"
assert "B-04" in titels["AI-agent wist productiedatabase van startup"]["checks"]
pi = titels["New prompt injection attack hijacks ChatGPT agents"]
assert pi["tab"] == "ai-security" and pi["checks"][:2] == ["H-01", "H-21"], pi
assert titels["OpenAI releases a new reasoning model"]["tab"] == "ai"

# 5. Elk bericht in precies één tabblad, geen URL dubbel
urls = [i["url"] for i in items] + [o["url"] for i in items for o in i["ook"]]
assert len(urls) == len(set(urls))

# 6. Nog eens ophalen: niets nieuws, niets dubbel; kapotte bron gemeld, de rest werkt
n = len(items)
d = nw.ophalen(nw.PAD, BRONNEN, nep_haal)
assert len(d["items"]) == n
assert d["bronnen"]["Kapot"]["ok"] is False and d["bronnen"]["Security.nl"]["ok"] is True

# 7. Geen entiteiten (billion laughs)
try:
    nw.lees_feed(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><rss><channel></channel></rss>')
    raise AssertionError("DTD niet geweigerd")
except ValueError:
    pass

# 7b. Kapotte XML (zoals soms bij Security.nl): toch de berichten
kapot = f"""<?xml version="1.0"?><rss><channel><title>x</title><p>
<item><title>Lek in &lt;router&gt; actief misbruikt</title><link>https://example.nl/1</link><pubDate>{uur(1)}</pubDate>
<description><![CDATA[<b>Patch</b> nu]]></description></item></channel></rss>""".encode()
k = nw.lees_feed(kapot)
assert k[0]["titel"] == "Lek in <router> actief misbruikt" and k[0]["tekst"] == "Patch nu" and k[0]["datum"], k
assert nw.andere_taal("Девушка жалуется на затягивание дела") and not nw.andere_taal("Ahold Delhaize hit by cyberattack")

# 8. De pagina, de RSS-feed en de teaser op de homepage
import api  # noqa: E402

c = api.app.test_client()
r = c.get("/nieuws")
html = r.get_data(as_text=True)
assert r.status_code == 200
assert html.count('role="tabpanel"') == 3
for tekst in ("AI-security", "Cybersecurity", "AI-nieuws", "Ook bij:", "Albert Heijn", "/check/H-01", "Vandaag"):
    assert tekst in html, tekst
assert 'style="' not in html and "<script>" not in html
rss = c.get("/nieuws.xml")
assert rss.status_code == 200 and rss.get_data(as_text=True).count("<item>") == n
assert "Uit het nieuws" in c.get("/").get_data(as_text=True)
print(f"ok: nieuws, {n} berichten in {len(set(i['tab'] for i in d['items']))} tabbladen")
