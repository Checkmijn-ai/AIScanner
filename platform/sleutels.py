"""Maakt het sleutelpaar waarmee de dagversie ondertekend wordt (eenmalig).

Gebruik: python platform/sleutels.py /opt/aiscan/sleutels
De privésleutel (dagversie.pem) blijft op de bouwserver, nooit in git. De publieke sleutel komt op de site.
"""
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

doel = Path(sys.argv[1] if len(sys.argv) > 1 else "sleutels")
doel.mkdir(parents=True, exist_ok=True)
priv = doel / "dagversie.pem"
if priv.exists():
    sys.exit(f"{priv} bestaat al; overschrijven zou alle oude handtekeningen ongeldig maken.")
key = ed25519.Ed25519PrivateKey.generate()
priv.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
os.chmod(priv, 0o600)
(doel / "dagversie.pub.pem").write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                                        serialization.PublicFormat.SubjectPublicKeyInfo))
print(f"Sleutelpaar gemaakt in {doel}. Bewaar een kopie van de privésleutel veilig offline.")
