"""Regressietest: de scanner moet in de demo-app precies deze fouten vinden. Draai met: python -m pytest tests"""
import json, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERWACHT = {  # scan-ID -> stukjes tekst die in een bevinding moeten staan
    "B-05": ["API-sleutel van OpenAI", "tests over te slaan", "zonder bevestiging", "automatisch goedgekeurd"],
    "B-06": ["lodahs 1.0.2: bekend kwaadaardig pakket", "invoice-pdf-ai-helper"],
    "C-01": ["eval()"], "C-06": ["stacktrace", "Lege catch"], "C-20": [".env", "dump", "AI-agent"],
    "D-02": ["mag falen"], "D-06": ["SAST", "afhankelijkheden"],
    "E-03": ["Secure of HttpOnly", "standaardwaarde", "vervaldatum"],
    "E-04": ["template string", "aan elkaar te plakken", "commando-injectie"],
    "E-05": ["Stripe", "git-geschiedenis"], "E-06": ["MD5", "Math.random"],
    "F-01": ["mysql2 2.3.0", "axios 0.21.1", "minimist 1.2.5"], "F-02": ["node 16"], "F-03": ["integriteit"],
    "H-02": ["eval(expr)"], "H-08": ["tokens"], "P-05": ["handtekening", "SSRF"],
    "U-01": ["gebouwde frontend", "browser"], "U-02": ["source maps"], "U-03": ["localStorage"],
    "U-07": ["postMessage", "dangerouslySetInnerHTML"], "W-03": ["publieke map"],
}


def test_demo():
    with tempfile.TemporaryDirectory() as tmp:
        demo, out = Path(tmp) / "demo", Path(tmp) / "out"
        subprocess.run([sys.executable, str(ROOT / "tests" / "maak_demo.py"), str(demo)], check=True)
        subprocess.run([sys.executable, "-m", "aiscan", str(demo), "--offline", "--out", str(out)], cwd=ROOT)
        data = json.loads((out / "rapport.json").read_text())
        checks = {c["id"]: c for c in data["checks"]}
        missing = []
        for cid, frags in VERWACHT.items():
            text = " ".join(b["titel"] + " " + b["bewijs"] + " " + b["bestand"] for b in checks[cid]["bevindingen"])
            missing += [f"{cid}: {f}" for f in frags if f not in text]
        assert not missing, missing
        # nooit een geheim in het rapport
        keys = json.loads((demo / ".git" / "aiscan-testsleutels.json").read_text())
        for f in ("rapport.html", "rapport.json"):
            text = (out / f).read_text()
            leaked = [k for k, v in keys.items() if v in text]
            assert not leaked, f"geheim zichtbaar in {f}: {leaked}"
        assert data["samenvatting"]["score"]["letter"] == "G"


def test_hersteld():
    with tempfile.TemporaryDirectory() as tmp:
        demo, out = Path(tmp) / "demo", Path(tmp) / "out"
        subprocess.run([sys.executable, str(ROOT / "tests" / "maak_demo.py"), str(demo), "--hersteld"], check=True)
        subprocess.run([sys.executable, "-m", "aiscan", str(demo), "--offline", "--out", str(out)], cwd=ROOT, capture_output=True)
        data = json.loads((out / "rapport.json").read_text())
        assert data["samenvatting"]["score"]["letter"] == "B", data["samenvatting"]["score"]
        assert data["samenvatting"]["ernst"]["Kritiek"] == 0 and data["samenvatting"]["ernst"]["Hoog"] == 0


def test_mcp():
    with tempfile.TemporaryDirectory() as tmp:
        demo = Path(tmp) / "demo"
        subprocess.run([sys.executable, str(ROOT / "tests" / "maak_demo.py"), str(demo)], check=True)
        msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                                                               "clientInfo": {"name": "test", "version": "1"}}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "aiscan_scan", "arguments": {"pad": str(demo)}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "aiscan_details", "arguments": {"scan_id": "E-05"}}}]
        p = subprocess.run([sys.executable, "-m", "aiscan.mcp_server"], cwd=ROOT, capture_output=True, text=True,
                           input="\n".join(json.dumps(m) for m in msgs) + "\n")
        out = {m["id"]: m for m in map(json.loads, p.stdout.splitlines())}
        assert out[1]["result"]["serverInfo"]["name"] == "aiscan"
        assert {t["name"] for t in out[2]["result"]["tools"]} == {"aiscan_scan", "aiscan_details"}
        text = out[3]["result"]["content"][0]["text"]
        assert "Scanscore: **G**" in text and "netwerk geblokkeerd (bevestigd)" in text
        keys = json.loads((demo / ".git" / "aiscan-testsleutels.json").read_text())
        assert not [k for k, v in keys.items() if v in text + out[4]["result"]["content"][0]["text"]]
        assert (demo / ".aiscan" / "rapport.html").exists()


if __name__ == "__main__":
    test_demo(); test_hersteld(); test_mcp()
    print("ok: demo, hersteld en MCP")
