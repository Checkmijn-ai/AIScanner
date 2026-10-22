"""Test van begin tot eind: dagversie bouwen, API starten, scan.md volgen zoals een agent, en knoeien proberen."""
import json, os, re, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "NO_PROXY": "*", "no_proxy": "*"}


def vrije_poort():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def test_platform():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    import base64
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        www, keys, demo = tmp / "www", tmp / "keys", tmp / "demo"
        ps, pa = vrije_poort(), vrije_poort()
        subprocess.run([sys.executable, str(ROOT / "platform" / "sleutels.py"), str(keys)], check=True, capture_output=True)
        subprocess.run([sys.executable, str(ROOT / "platform" / "build_daily.py"), "--public", str(www / "aiscan"), "--ghsa", "-",
                        "--index", str(ROOT / "aiscan" / "data" / "advisories.json.gz"), "--sleutel", str(keys / "dagversie.pem"),
                        "--site", f"http://127.0.0.1:{ps}/aiscan", "--api", f"http://127.0.0.1:{pa}"], check=True, capture_output=True)
        m = json.loads((www / "aiscan" / "latest.json").read_text())
        # handtekening van het manifest nakijken
        pub = serialization.load_pem_public_key((www / "aiscan" / "public-key.pem").read_bytes())
        body = json.dumps({k: v for k, v in m.items() if k != "handtekening"}, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
        pub.verify(base64.b64decode(m["handtekening"]["waarde"]), body)
        subprocess.run([sys.executable, str(ROOT / "tests" / "maak_demo.py"), str(demo), "--hersteld"], check=True, capture_output=True)
        web = subprocess.Popen([sys.executable, "-m", "http.server", str(ps), "--bind", "127.0.0.1"], cwd=www,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        api = subprocess.Popen([sys.executable, str(ROOT / "platform" / "api.py")], env={**ENV, "AISCAN_PORT": str(pa),
                               "AISCAN_PUBLIC": str(www / "aiscan"), "AISCAN_DB": str(tmp / "db.sqlite"),
                               "AISCAN_SITE": f"http://127.0.0.1:{pa}"}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(2)
            md = (www / "aiscan" / "scan.md").read_text()
            blocks = re.findall(r"```\n(.*?)\n```", re.sub(r"```(python|yaml)\n.*?\n```", "", md, flags=re.S), re.S)
            run = lambda cmd, cwd: subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=cwd, env=ENV)
            work = Path(run(blocks[0], tmp).stdout.strip())
            assert run(blocks[1], work).returncode == 0
            # stap 3: controle van handtekening en controlegetal, met het script uit scan.md (alleen standaardbibliotheek)
            script = re.search(r"```python\n(.*?)\n```", md, re.S).group(1)
            (work / "controleer.py").write_text(script)
            ok = run(blocks[2], work)
            assert ok.returncode == 0 and ok.stdout.startswith("OK"), (ok.stdout, ok.stderr)
            # geknoeid manifest (zelfde controlegetal, andere inhoud zonder nieuwe handtekening) wordt geweigerd
            echt_manifest = (www / "aiscan" / "latest.json").read_text()
            (www / "aiscan" / "latest.json").write_text(json.dumps({**m, "scanner_versie": "9.9.9"}))
            nok = run(blocks[2], work)
            assert nok.returncode == 1 and "handtekening" in nok.stdout, nok.stdout
            (www / "aiscan" / "latest.json").write_text(echt_manifest)
            # geknoeide scanner wordt geweigerd
            pyz = work / "checkmijn.pyz"; echt_pyz = pyz.read_bytes(); pyz.write_bytes(echt_pyz + b"x")
            assert run(blocks[2], work).returncode == 1
            pyz.write_bytes(echt_pyz)
            # één domein: de API geeft ook de scanner van vandaag, en alleen die
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            assert opener.open(f"http://127.0.0.1:{pa}/{m['bestand']}").read() == echt_pyz
            try:
                opener.open(f"http://127.0.0.1:{pa}/checkmijn-2000-01-01.pyz"); raise AssertionError("oude dagversie gaf geen 404")
            except urllib.error.HTTPError as e:
                assert e.code == 404
            nonce = run(blocks[3], work).stdout.strip()
            scan = run(blocks[4].replace("PROJECTMAP", str(demo)).replace("NONCE", nonce), work)
            assert scan.returncode in (0, 2), scan.stderr
            tel = next(bl for bl in blocks if "meetellen" in bl)
            t1 = run(tel.replace("PROJECTMAP", str(demo)), work)
            assert t1.returncode == 0 and "Meegeteld" in t1.stdout, (t1.stdout, t1.stderr)
            t2 = run(tel.replace("PROJECTMAP", str(demo)), work)
            assert "al meegeteld" in t2.stderr, (t2.stdout, t2.stderr)
            inl = next(bl for bl in blocks if "inleveren" in bl)
            res = run(inl, work)
            assert res.returncode == 0, res.stderr
            r = json.loads(res.stdout)
            assert r["score"] == "C" and r["soort"] == "Zelfscan"
            assert run(inl, work).returncode != 0, "sessiecode mocht geen tweede keer werken"
            b = json.loads((work / "rapport" / "bewijs.json").read_text())
            n2 = run(blocks[3], work).stdout.strip()
            code, d = post(f"http://127.0.0.1:{pa}/api/v1/resultaat", {**b, "nonce": n2, "score": {**b["score"], "letter": "A"}})
            assert code == 422 and "klopt niet" in d["fout"], d
            n3 = run(blocks[3], work).stdout.strip()
            code, d = post(f"http://127.0.0.1:{pa}/api/v1/resultaat", {**b, "nonce": n3, "scanner": {**b["scanner"], "sha256": "0" * 64}})
            assert code == 422 and "Onbekende scanner" in d["fout"], d
            n4 = run(blocks[3], work).stdout.strip()
            res2 = [dict(x) for x in b["resultaten"]]
            res2[0]["status"], res2[0]["zwaarste"], res2[0]["aantal"] = "Bevinding", "Kritiek", 1
            code, d = post(f"http://127.0.0.1:{pa}/api/v1/resultaat", {**b, "nonce": n4, "resultaten": res2})
            assert code == 422, d   # score C klopt dan niet meer
            # een bewijs dat zich als keuring (niveau 2) voordoet, krijgt toch de schaal van een zelfscan
            n5 = run(blocks[3], work).stdout.strip()
            code, d = post(f"http://127.0.0.1:{pa}/api/v1/resultaat", {**b, "nonce": n5, "niveau": 2, "score": {**b["score"], "letter": "A"}})
            assert code == 422, d
            # een scanner van vóór 22 oktober gaf nog een B: aanvaard, maar bewaard als C
            n6 = run(blocks[3], work).stdout.strip()
            code, d = post(f"http://127.0.0.1:{pa}/api/v1/resultaat", {**b, "nonce": n6, "score": {**b["score"], "letter": "B"}})
            assert code == 201 and d["score"] == "C", d
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            assert b"Scanscore" in opener.open(r["badge"]).read()
            svg = opener.open(r["badge"]).read()
            assert b"ZELFSCAN" in svg and b"stroke-dasharray" in svg
            assert b"ZELFSCAN" in opener.open(r["pagina"]).read()
        finally:
            web.terminate(); api.terminate()


if __name__ == "__main__":
    test_platform()
    print("ok: dagversie, handtekening, agentstroom en weigeringen")
