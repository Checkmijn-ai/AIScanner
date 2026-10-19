"""Versies vergelijken voor npm (semver) en PyPI (PEP 440)."""
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


def key(eco: str, v: str):
    if v is None:
        return None
    if eco == "npm":
        return _npm_key(v)
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
