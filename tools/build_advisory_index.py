"""Bouwt een compacte, offline lekkenindex (npm en PyPI) uit de GitHub Advisory Database (OSV-formaat).

Gebruik: python tools/build_advisory_index.py <pad naar advisory-database> <uitvoer.json.gz>
Bron: https://github.com/github/advisory-database (CC-BY 4.0)
"""
import gzip, json, os, re, sys
src, dst = sys.argv[1], sys.argv[2]
idx = {"npm": {}, "PyPI": {}}
n = 0
for dp, _, fns in os.walk(os.path.join(src, "advisories", "github-reviewed")):
    for fn in fns:
        if not fn.endswith(".json"):
            continue
        try:
            d = json.load(open(os.path.join(dp, fn)))
        except Exception:
            continue
        if d.get("withdrawn"):
            continue
        sev = (d.get("database_specific") or {}).get("severity") or ""
        for a in d.get("affected", []):
            eco = a.get("package", {}).get("ecosystem")
            if eco not in idx:
                continue
            name = a["package"]["name"]
            if eco == "PyPI":
                import re
                name = re.sub(r"[-_.]+", "-", name).lower()
            ranges = []
            for r in a.get("ranges", []):
                if r.get("type") in ("SEMVER", "ECOSYSTEM"):
                    ranges.append(r.get("events", []))
            rec = {"id": d["id"], "cve": [x for x in d.get("aliases", []) if x.startswith("CVE-")],
                   "sev": sev, "sum": (d.get("summary") or "")[:200], "r": ranges,
                   "v": a.get("versions", [])[:500],
                   "mal": bool(re.search(r"^(malicious code in|embedded malicious code)|\bis malware\b|contains malware|malicious (package|version|code)", (d.get("summary") or ""), re.I)),
                   "pub": (d.get("published") or "")[:10]}
            idx[eco].setdefault(name, []).append(rec)
            n += 1
meta = {"bron": "GitHub Advisory Database (github-reviewed)", "aantal": n, "stand": sys.argv[3] if len(sys.argv) > 3 else ""}
with gzip.open(dst, "wt") as f:
    json.dump({"meta": meta, "idx": idx}, f, separators=(",", ":"))
if __name__ == "__main__":
    print(meta, {k: len(v) for k, v in idx.items()})
