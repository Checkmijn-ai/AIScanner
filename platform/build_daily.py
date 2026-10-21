"""Bouwt elke nacht de dagversie van de scanner en publiceert ze op de site.

Stappen:
 1. GitHub Advisory Database bijwerken (git pull, alleen github-reviewed).
 2. Lekkenindex van vandaag bouwen.
 3. Catalogus van checks controleren en de changelog bijwerken.
 4. De scanner inpakken als één bestand: checkmijn-JJJJ-MM-DD.pyz (met de pure-Python-afhankelijkheden erin).
 5. Controlegetal (SHA-256) berekenen en het manifest ondertekenen met een Ed25519-sleutel.
 6. Publiceren: latest.json, versies.json, checks.json, changelog.json, public-key.pem, de .pyz en scan.md.
 7. Oude dagversies opruimen (standaard 14 bewaren).

Gebruik (zie crontab.txt):
  python platform/build_daily.py --public /var/www/checkmijn --ghsa /opt/checkmijn/ghsa \\
        --sleutel /opt/checkmijn/sleutels/dagversie.pem --site https://checkmijn.ai --api https://api.checkmijn.ai
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "platform"))
import catalogus  # noqa: E402

VENDOR = ["yaml", "jinja2", "markupsafe", "packaging", "requests", "urllib3", "idna", "certifi", "charset_normalizer"]

BOOTSTRAP = '''"""checkmijn.ai dagversie {dag}: pakt zichzelf uit in een tijdelijke map, draait en ruimt op."""
import atexit, os, shutil, sys, tempfile, zipfile
pyz = os.path.abspath(sys.argv[0])
tmp = tempfile.mkdtemp(prefix="checkmijn-")
atexit.register(shutil.rmtree, tmp, True)
with zipfile.ZipFile(pyz) as z:
    z.extractall(tmp)
sys.path[:0] = [tmp, os.path.join(tmp, "_vendor")]
os.environ["AISCAN_PYZ"] = pyz
os.environ["AISCAN_DAGVERSIE"] = "{dag}"
if len(sys.argv) > 1 and sys.argv[1] in ("sessie", "inleveren", "meetellen"):
    from aiscan.client import main as c
    sys.exit(c(sys.argv[1:]))
elif len(sys.argv) > 1 and sys.argv[1] == "mcp":
    from aiscan.mcp_server import main as m
    sys.argv = sys.argv[:1]
    m()
else:
    from aiscan.__main__ import main as m
    sys.exit(m())
'''


def log(*a):
    print(dt.datetime.now().strftime("%H:%M:%S"), *a, flush=True)


def _git_commit() -> str:
    try:
        return subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def update_ghsa(ghsa: Path):
    def kloon():
        log("GitHub Advisory Database klonen (±500 MB)")
        subprocess.run(["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--sparse",
                        "https://github.com/github/advisory-database", str(ghsa)], check=True)
        subprocess.run(["git", "-C", str(ghsa), "sparse-checkout", "set", "advisories/github-reviewed"], check=True)

    if not (ghsa / ".git").exists():
        shutil.rmtree(ghsa, ignore_errors=True)
        return kloon()
    log("GitHub Advisory Database bijwerken")
    # Een ondiepe kloon kan niet 'pullen' (geen gedeelde geschiedenis): haal de nieuwste stand op en zet die vast.
    g = lambda *a: subprocess.run(["git", "-C", str(ghsa), *a], capture_output=True, text=True)  # noqa: E731
    if g("fetch", "-q", "--depth", "1", "origin", "main").returncode == 0 and g("reset", "-q", "--hard", "FETCH_HEAD").returncode == 0:
        return
    log("Bijwerken mislukt; opnieuw klonen")
    shutil.rmtree(ghsa, ignore_errors=True)
    kloon()


def bouw_index(ghsa: Path, doel: Path, dag: str):
    spec = importlib.util.spec_from_file_location("bai", ROOT / "tools" / "build_advisory_index.py")
    argv = sys.argv
    try:
        sys.argv = ["bai", str(ghsa), str(doel), dag]
        spec.loader.exec_module(importlib.util.module_from_spec(spec))
    finally:
        sys.argv = argv


def vendor(dest: Path):
    dest.mkdir(parents=True, exist_ok=True)
    for name in VENDOR:
        mod = importlib.util.find_spec(name)
        if not mod or not mod.submodule_search_locations:
            raise SystemExit(f"Pakket '{name}' niet gevonden op de bouwmachine: pip install -r requirements.txt")
        src = Path(list(mod.submodule_search_locations)[0])
        shutil.copytree(src, dest / name, ignore=shutil.ignore_patterns("__pycache__", "*.so", "*.pyd", "*.dylib", "tests"))


def canoniek(d: dict) -> bytes:
    return json.dumps({k: v for k, v in d.items() if k != "handtekening"}, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode()


def onderteken(manifest: dict, sleutel: Path | None):
    if not sleutel:
        manifest["handtekening"] = None
        return manifest
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_pem_private_key(sleutel.read_bytes(), password=None)
    manifest["handtekening"] = {"algoritme": "Ed25519", "waarde": base64.b64encode(key.sign(canoniek(manifest))).decode()}
    return manifest


def main(argv=None):
    ap = argparse.ArgumentParser(description="Dagversie van de checkmijn.ai-scanner bouwen en publiceren")
    ap.add_argument("--public", required=True, help="map die de website publiek serveert, bv. /var/www/checkmijn")
    ap.add_argument("--ghsa", required=True, help="lokale kopie van github/advisory-database")
    ap.add_argument("--sleutel", default=None, help="privésleutel (PEM, Ed25519) om het manifest te ondertekenen")
    ap.add_argument("--site", required=True, help="publiek adres waar --public staat, bv. https://checkmijn.ai")
    ap.add_argument("--api", required=True, help="adres van de API, bv. https://api.checkmijn.ai")
    ap.add_argument("--instructie", default=None,
                    help="publiek adres van scan.md, als dat anders is dan --site (bv. https://checkmijn.ai/scan.md)")
    ap.add_argument("--bewaar", type=int, default=14, help="aantal dagversies dat online blijft")
    ap.add_argument("--dag", default=None, help="datum van de dagversie (standaard vandaag, UTC)")
    ap.add_argument("--zonder-update", action="store_true", help="GHSA niet bijwerken (testen)")
    ap.add_argument("--index", default=None, help="bestaande lekkenindex gebruiken in plaats van GHSA (testen)")
    a = ap.parse_args(argv)

    dag = a.dag or dt.datetime.now(dt.timezone.utc).date().isoformat()
    pub = Path(a.public)
    pub.mkdir(parents=True, exist_ok=True)
    ghsa = Path(a.ghsa)
    site = a.site.rstrip("/")

    # 1-2. lekkendatabank
    if not a.zonder_update and not a.index:
        update_ghsa(ghsa)
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp) / "stage"
        shutil.copytree(ROOT / "aiscan", stage / "aiscan", ignore=shutil.ignore_patterns("__pycache__"))
        if a.index:
            shutil.copy(a.index, stage / "aiscan" / "data" / "advisories.json.gz")
        else:
            log("Lekkenindex bouwen")
            bouw_index(ghsa, stage / "aiscan" / "data" / "advisories.json.gz", dag)

        # 3. catalogus
        checks = catalogus.laad()
        fouten = catalogus.controleer(checks)
        if fouten:
            raise SystemExit("Catalogus niet in orde:\n" + "\n".join(fouten))
        pub_cat = catalogus.publiek(checks)
        oud_pad = pub / "checks.json"
        oud = json.loads(oud_pad.read_text())["checks"] if oud_pad.exists() else []
        nieuw = catalogus.verschil(oud, pub_cat["checks"], dag) if oud else []
        cl_pad = pub / "changelog.json"
        changelog = json.loads(cl_pad.read_text()) if cl_pad.exists() else []
        changelog = nieuw + changelog
        log(f"Catalogus: {pub_cat['aantal_actief']} actieve checks, {len(nieuw)} wijziging(en)")

        # 4. inpakken
        log("Afhankelijkheden meenemen (alleen pure Python)")
        vendor(stage / "_vendor")
        (stage / "__main__.py").write_text(BOOTSTRAP.format(dag=dag))
        naam = f"checkmijn-{dag}.pyz"
        doel = pub / naam
        zipapp.create_archive(stage, doel, interpreter="/usr/bin/env python3", compressed=True)
        import gzip
        meta = json.load(gzip.open(stage / "aiscan" / "data" / "advisories.json.gz", "rt"))["meta"]
        h = hashlib.sha256()  # zelfde berekening als aiscan.runner.ruleset_hash, zodat het bewijs overeenkomt
        for p in sorted((stage / "aiscan" / "data").glob("*")):
            h.update(p.name.encode())
            h.update(p.read_bytes())
        regelset = h.hexdigest()[:12]
        sys.path.insert(0, str(ROOT))
        from aiscan import __version__

    # 5. controlegetal en manifest
    data = doel.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    manifest = {
        "dagversie": dag, "scanner_versie": __version__, "bestand": naam, "url": f"{site}/{naam}",
        "sha256": sha, "grootte": len(data), "databank": {"bron": meta.get("bron"), "stand": meta.get("stand"),
                                                         "aantal": meta.get("aantal")},
        "catalogus": {"actief": pub_cat["aantal_actief"], "sha256": pub_cat["sha256"]}, "regelset": regelset,
        "api": a.api.rstrip("/"), "instructie": a.instructie or f"{site}/scan.md",
        "gebouwd": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "bron": {"repository": "https://github.com/" + os.environ.get("GITHUB_REPOSITORY", "Checkmijn-ai/AIScanner"),
                 "commit": os.environ.get("GITHUB_SHA") or _git_commit(), "licentie": "EUPL-1.2"},
    }
    onderteken(manifest, Path(a.sleutel) if a.sleutel else None)

    # 6. publiceren
    versies_pad = pub / "versies.json"
    versies = json.loads(versies_pad.read_text()) if versies_pad.exists() else {}
    versies[dag] = {"sha256": sha, "bestand": naam, "catalogus_sha256": pub_cat["sha256"], "regelset": regelset,
                    "checks": [c["id"] for c in pub_cat["checks"] if c["status"] == "actief"], "scanner_versie": __version__}
    # 7. opruimen
    for oude in sorted(versies)[:-a.bewaar]:
        f = pub / versies[oude]["bestand"]
        if f.exists():
            f.unlink()
        versies[oude]["verwijderd"] = True
    for naam_, inhoud in (("latest.json", manifest), ("versies.json", versies), ("checks.json", pub_cat),
                          ("changelog.json", changelog)):
        tmpf = pub / (naam_ + ".tmp")
        tmpf.write_text(json.dumps(inhoud, indent=1, ensure_ascii=False))
        tmpf.replace(pub / naam_)
    if a.sleutel:
        from cryptography.hazmat.primitives import serialization
        key = serialization.load_pem_private_key(Path(a.sleutel).read_bytes(), password=None)
        (pub / "public-key.pem").write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    from jinja2 import Template
    tpl = Template((ROOT / "platform" / "templates" / "scan.md.j2").read_text())
    workflow = (ROOT / "voorbeelden" / "checkmijn.yml").read_text()
    (pub / "scan.md").write_text(tpl.render(m=manifest, workflow=workflow))
    shutil.copy(ROOT / "voorbeelden" / "checkmijn.yml", pub / "checkmijn.yml")
    log(f"Gepubliceerd: {naam} · sha256 {sha[:16]}… · databank {meta.get('stand')} ({meta.get('aantal')} lekken)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
