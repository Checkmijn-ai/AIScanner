"""De website: elke pagina laadt, geen inline scripts of stijlen (strikte CSP), geen kapotte interne links."""
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
tmp = Path(tempfile.mkdtemp())
(tmp / "scan.md").write_text("# test\n")
os.environ.update({"AISCAN_DB": str(tmp / "t.db"), "AISCAN_PUBLIC": str(tmp)})
os.environ.pop("AISCAN_PUBLIC_URL", None)
sys.path.insert(0, str(ROOT / "platform"))
import api  # noqa: E402

c = api.app.test_client()
paginas = ["/", "/hoe-het-werkt", "/niveaus", "/wat-we-controleren", "/score-uitleg", "/waarom", "/bureaus",
           "/opdrachtgevers", "/vertrouwen", "/framework", "/vragen", "/contact", "/scan", "/rapport/x",
           "/wat-je-krijgt", "/open-source", "/check/E-05", "/check/W-13", "/voorbeeldrapport", "/voorbeeldrapport/na", "/nieuws", "/cra", "/crosswalk"]
links = set()
for p in paginas:
    r = c.get(p)
    html = r.get_data(as_text=True)
    assert r.status_code == 200, (p, r.status_code)
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp.split("script-src")[1].split(";")[0], (p, csp)
    assert "<script>" not in html and " onclick=" not in html, p
    if p not in ("/rapport/x", "/voorbeeldrapport", "/voorbeeldrapport/na"):
        assert 'style="' not in html, f"inline stijl op {p}"
        assert "style-src 'self';" in csp, p
    links |= set(re.findall(r'href="(/[^"#?]*)', html))
kapot = [l for l in sorted(links) if c.get(l).status_code >= 400 and l not in ("/latest.json", "/checks.json",
         "/versies.json", "/changelog.json", "/public-key.pem", "/checkmijn.yml", "/scan.md")]
assert not kapot, kapot
assert c.get("/bestaat-niet").status_code == 404
assert "Disallow: /rapport/" in c.get("/robots.txt").get_data(as_text=True)
assert c.get("/framework.csv").get_data(as_text=True).count("\n") >= 46
cw = c.get("/crosswalk.csv").get_data(as_text=True)
assert cw.count("ISO/IEC 27001:2022") == 93, "alle 93 controls van bijlage A"
assert "8.28" in c.get("/check/C-01").get_data(as_text=True), "checkpagina toont de ISO-controls"
print(f"ok: website, {len(paginas)} pagina's, {len(links)} interne links")
