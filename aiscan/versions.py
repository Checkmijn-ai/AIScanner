"""Versies vergelijken: npm (semver), PyPI (PEP 440), en een algemene vergelijking voor Composer, Go, RubyGems en Maven."""
from __future__ import annotations
import re
from packaging.version import Version, InvalidVersion

_SEMVER = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$")


def _npm_key(v: str):
    m = _SEMVER.match(v.strip())
    if not m:
        return None
    pre = m.group(4)
    prekey = (1,) if pre is None else (0,) + tuple((0, int(x)) if x.isdigit() else (1, x) for x in pre.split("."))
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0), prekey)


_RELEASE_WOORDEN = {"final", "ga", "release", "rel", "sp"}


def _algemeen_key(v: str):
    """1.2.3 < 1.2.10; 1.2.3-beta < 1.2.3; 1.2.3.RELEASE == 1.2.3 (Maven); v1.2.3 == 1.2.3 (Go, Composer)."""
    v = v.strip().lstrip("vV")
    if not v or not v[0].isdigit():
        return None
    delen = re.split(r"[.\-+_]", v.split("+")[0])
    getallen, rest = [], []
    for i, d in enumerate(delen):
        if d.isdigit() and not rest:
            getallen.append(int(d))
        elif d:
            mm = re.match(r"^(\d+)([A-Za-z].*)$", d)
            if mm and not rest:  # 1.2.3rc1
                getallen.append(int(mm.group(1)))
                rest.append(mm.group(2).lower())
            else:
                rest.append(d.lower())
    rest = [x for x in rest if x not in _RELEASE_WOORDEN]
    getallen = (getallen + [0] * 4)[:6]
    pre = (1,) if not rest else (0,) + tuple((0, int(x)) if x.isdigit() else (1, x) for x in rest)
    return (tuple(getallen), pre)


def key(eco: str, v: str):
    if v is None:
        return None
    if eco == "npm":
        return _npm_key(v)
    if eco in ("Packagist", "Go", "RubyGems", "Maven"):
        return _algemeen_key(v)
    try:
        return Version(v)
    except InvalidVersion:
        return None


def affected(eco: str, version: str, rec: dict) -> bool:
    if version in rec.get("v", []):
        return True
    k = key(eco, version)
    if k is None:
        return False
    for events in rec.get("r", []):
        lo, inside = None, False
        for ev in events:
            if "introduced" in ev:
                intro = ev["introduced"]
                lo = key(eco, "0.0.0" if intro == "0" else intro) if eco == "npm" else key(eco, "0" if intro == "0" else intro)
                if lo is not None and k >= lo:
                    inside = True
            elif "fixed" in ev:
                f = key(eco, ev["fixed"])
                if inside and f is not None and k < f:
                    return True
                inside = False
            elif "last_affected" in ev:
                f = key(eco, ev["last_affected"])
                if inside and f is not None and k <= f:
                    return True
                inside = False
        if inside:
            return True
    return False


def fixed_in(eco: str, rec: dict):
    out = []
    for events in rec.get("r", []):
        for ev in events:
            if "fixed" in ev:
                out.append(ev["fixed"])
    return out
