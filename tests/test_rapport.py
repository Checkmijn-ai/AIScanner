"""Test van de versleutelde rapporten: OIDC-token, inleveren, ophalen, ontsleutelen en weigeringen."""
import base64
import json
import os
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
tmp = Path(tempfile.mkdtemp())
os.environ.update({"AISCAN_DB": str(tmp / "t.db"), "AISCAN_OIDC_ISSUER": "https://token.example",
                   "AISCAN_OIDC_JWKS": "unused", "AISCAN_SITE_ORIGIN": "https://checkmijn.ai"})
sys.path.insert(0, str(ROOT / "platform"))
import api  # noqa: E402

b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")  # noqa: E731
ib = lambda i: b64(i.to_bytes((i.bit_length() + 7) // 8, "big"))  # noqa: E731
sleutel = rsa.generate_private_key(public_exponent=65537, key_size=2048)
n = sleutel.public_key().public_numbers()
api._JWKS.update({"tijd": time.time(), "sleutels": {"t1": {"kty": "RSA", "kid": "t1", "n": ib(n.n), "e": ib(n.e)}}})


def token(**over):
    t = int(time.time())
    c = {"iss": "https://token.example", "aud": "checkmijn.ai", "repository_id": "42", "nbf": t - 5, "exp": t + 600, **over}
    kop = b64(json.dumps({"alg": "RS256", "kid": "t1"}).encode())
    inh = b64(json.dumps(c).encode())
    return f"{kop}.{inh}." + b64(sleutel.sign(f"{kop}.{inh}".encode(), padding.PKCS1v15(), hashes.SHA256()))


k, iv = AESGCM.generate_key(bit_length=256), os.urandom(12)
geheim = b"<html>rapport met bevindingen</html>"
body = {"versie": 1, "alg": "A256GCM", "iv": b64(iv), "data": b64(AESGCM(k).encrypt(iv, geheim, None))}
c = api.app.test_client()

r = c.post("/api/v1/rapport", json=body, headers={"Authorization": f"Bearer {token()}"})
assert r.status_code == 201, r.get_json()
rid = r.get_json()["id"]
assert r.get_json()["pagina"] == f"https://checkmijn.ai/rapport/{rid}"

r = c.get(f"/api/v1/rapport/{rid}")
assert r.status_code == 200 and r.headers["Access-Control-Allow-Origin"] == "https://checkmijn.ai"
d = r.get_json()
u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))  # noqa: E731
assert AESGCM(k).decrypt(u(d["iv"]), u(d["data"]), None) == geheim
assert geheim not in (tmp / "t.db").read_bytes(), "de server mag het rapport niet leesbaar bewaren"

for naam, tok in [("geen token", None), ("verkeerde doelgroep", token(aud="iemand-anders")),
                  ("verkeerde uitgever", token(iss="https://kwaad.example")), ("verlopen", token(exp=int(time.time()) - 3600)),
                  ("vervalst", token()[:-4] + "AAAA")]:
    h = {"Authorization": f"Bearer {tok}"} if tok else {}
    r = c.post("/api/v1/rapport", json=body, headers=h)
    assert r.status_code == 401, (naam, r.status_code, r.get_json())

assert c.post("/api/v1/rapport", json={"versie": 1}, headers={"Authorization": f"Bearer {token()}"}).status_code == 422
assert c.get("/api/v1/rapport/bestaat-niet").status_code == 404
print("ok: versleuteld rapport, OIDC en weigeringen")
