"""De GitHub Action faalt dicht: zonder geldige sleutel of handtekening geen scan."""
import base64
import importlib.util
import json
import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("GITHUB_REPOSITORY", "jan/app")
spec = importlib.util.spec_from_file_location("scan_ci", ROOT / "action" / "scan_ci.py")
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)
tmp = Path(tempfile.mkdtemp())


def pem(pub):
    return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def onderteken(m, priv):
    data = json.dumps(m, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return {**m, "handtekening": {"alg": "Ed25519", "waarde": base64.b64encode(priv.sign(data)).decode()}}


def stopt(m, sleutel):
    try:
        sc.controleer_handtekening(m, sleutel)
    except SystemExit as e:
        return str(e)
    return ""


priv = ed25519.Ed25519PrivateKey.generate()
goed = tmp / "goed.pem"
goed.write_bytes(pem(priv.public_key()))
m = onderteken({"dagversie": "2026-10-21", "sha256": "ab" * 32, "url": "https://x/y.pyz"}, priv)

assert sc.controleer_handtekening(m, goed) == "geldig (Ed25519)"
assert "geen publieke sleutel" in stopt(m, tmp / "bestaat-niet.pem")                       # ontbreekt: dicht
(tmp / "leeg.pem").write_text("onzin")
assert "geen publieke sleutel" in stopt(m, tmp / "leeg.pem")                              # onherkenbaar: dicht
rsa_pem = tmp / "rsa.pem"
rsa_pem.write_bytes(pem(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()))
assert "geen Ed25519" in stopt(m, rsa_pem)                                                  # verkeerd soort sleutel
assert "niet ondertekend" in stopt({k: v for k, v in m.items() if k != "handtekening"}, goed)
assert "klopt niet" in stopt({**m, "sha256": "cd" * 32}, goed)                              # manifest aangepast
ander = ed25519.Ed25519PrivateKey.generate()
assert "klopt niet" in stopt(onderteken({"dagversie": "2026-10-21", "sha256": "ab" * 32, "url": "https://x/y.pyz"}, ander), goed)
echt = serialization.load_pem_public_key((ROOT / "action" / "public-key.pem").read_bytes())
assert isinstance(echt, ed25519.Ed25519PublicKey)                                         # de sleutel in de repo
assert "klopt niet" in stopt(m, ROOT / "action" / "public-key.pem")                         # onze sleutel, andere ondertekenaar
print("ok: handtekening faalt dicht")
