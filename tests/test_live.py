"""Live-scan afgebakend: geen interne adressen, doorsturen alleen binnen dezelfde site, altijd met certificaatcontrole."""
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from aiscan.checks import live  # noqa: E402

# 1. interne adressen
for h in ("127.0.0.1", "localhost", "10.1.2.3", "192.168.0.1", "169.254.169.254", "::1"):
    assert live.intern_adres(h), h
assert live.intern_adres("8.8.8.8") is None

# 2. zelfde site
assert live.zelfde_domein("example.com", "www.example.com") and live.zelfde_domein("WWW.example.com.", "example.com")
assert not live.zelfde_domein("evil.com", "example.com") and not live.zelfde_domein("example.com.evil.com", "example.com")
assert not live.zelfde_domein("api.example.com", "example.com")

# 3. een scan op een intern adres wordt geweigerd, voor elke live-check, zonder verbinding te maken
proj = SimpleNamespace(url="http://169.254.169.254/latest/meta-data", offline=False)
r = live._need(proj, "D-12")
assert r.status == "Niet gescand" and "intern adres" in r.reden, r.reden
assert "ports" not in proj._live

# 4. doorsturen: alleen binnen dezelfde site en naar publieke adressen
class Antw:
    def __init__(self, code, loc=None):
        self.status_code, self.headers, self.history, self.url = code, ({"Location": loc} if loc else {}), [], ""
        self.raw = SimpleNamespace(headers=SimpleNamespace(getlist=lambda n: []))
bezocht = []
def nep_get(url, **kw):
    assert kw.get("allow_redirects") is False and "verify" not in kw  # requests controleert certificaten standaard
    bezocht.append(url)
    return {"https://example.com/": Antw(301, "https://www.example.com/"),
            "https://www.example.com/": Antw(302, "https://evil.example.net/steel"),
            "https://a.example.org/": Antw(302, "https://a.example.org/intern")}.get(url, Antw(200))
import requests  # noqa: E402
echt_get, echt_intern = requests.get, live.intern_adres
requests.get = nep_get
live.intern_adres = lambda h: "10.0.0.5" if "a.example.org" in h else None
try:
    resp = live._haal("https://example.com/", "example.com")
    assert bezocht == ["https://example.com/", "https://www.example.com/"], bezocht  # evil.example.net niet gevolgd
    assert len(resp.history) == 1
    bezocht.clear()
    live._haal("https://a.example.org/", "a.example.org")
    assert bezocht == ["https://a.example.org/"], bezocht  # naar een intern adres: niet gevolgd
finally:
    requests.get, live.intern_adres = echt_get, echt_intern

# 5. nergens meer verify=False, behalve de aparte TLS-test (Y-01)
src = (ROOT / "aiscan" / "checks" / "live.py").read_text()
assert "verify=False" not in src and src.count("CERT_NONE") == 1
print("ok: live-scan afgebakend")
