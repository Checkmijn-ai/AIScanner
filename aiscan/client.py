"""Kleine client voor de API: sessiecode halen, bewijs inleveren en (met toestemming) meetellen.
Alleen bewijs.json gaat naar buiten (geen code, geen paden), en bij meetellen een onomkeerbare projectcode."""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request


def _post(url, data: bytes):
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except Exception:
            return e.code, {"fout": e.reason}
    except urllib.error.URLError as e:
        return 0, {"fout": f"API niet bereikbaar: {e.reason}"}


def projectcode(map_: str) -> str:
    """Een vaste, onomkeerbare code per project: sha256 van de eerste commit (of, zonder git, van de mapnaam)."""
    import hashlib
    import os
    import subprocess
    sleutel = ""
    try:
        uit = subprocess.run(["git", "-C", map_, "rev-list", "--max-parents=0", "HEAD"], capture_output=True, text=True,
                             timeout=20).stdout.split()
        sleutel = sorted(uit)[0] if uit else ""
    except Exception:
        pass
    if not sleutel:
        sleutel = "map:" + os.path.basename(os.path.abspath(map_))
    return hashlib.sha256(("checkmijn:" + sleutel).encode()).hexdigest()


def main(argv):
    if len(argv) < 2 or argv[0] not in ("sessie", "inleveren", "meetellen"):
        print("Gebruik: aiscan sessie API_URL  |  aiscan inleveren bewijs.json API_URL  |  "
              "aiscan meetellen bewijs.json API_URL [PROJECTMAP]", file=sys.stderr)
        return 64
    if argv[0] == "meetellen":
        if len(argv) < 3:
            print("Gebruik: aiscan meetellen bewijs.json API_URL [PROJECTMAP]", file=sys.stderr)
            return 64
        bewijs = json.load(open(argv[1], "rb"))
        body = json.dumps({"bewijs": bewijs, "project": projectcode(argv[3] if len(argv) > 3 else ".")}).encode()
        code, d = _post(argv[2].rstrip("/") + "/api/v1/telling/zelf", body)
        if code in (200, 201):
            print(d.get("melding", "Meegeteld."))
            return 0
        print(f"Niet meegeteld ({code}): {d.get('fout', d)}", file=sys.stderr)
        return 1
    if argv[0] == "sessie":
        code, d = _post(argv[1].rstrip("/") + "/api/v1/sessie", b"{}")
        if code == 200:
            print(d["nonce"])
            return 0
    else:
        if len(argv) < 3:
            print("Gebruik: aiscan inleveren bewijs.json API_URL", file=sys.stderr)
            return 64
        data = open(argv[1], "rb").read()
        json.loads(data)  # alleen geldige JSON versturen
        code, d = _post(argv[2].rstrip("/") + "/api/v1/resultaat", data)
        if code == 201:
            print(json.dumps(d, indent=1, ensure_ascii=False))
            return 0
    print(f"Geweigerd ({code}): {d.get('fout', d)}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
