"""Rapport schrijven: HTML (voor mensen) en JSON (voor het platform)."""
from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .core import ERNST_ORDE

TPL = Path(__file__).resolve().parent / "templates"


def statusclass(s):
    return {"Geen bevinding": "st-ok", "Bevinding": "st-Bevinding", "Niet van toepassing": "st-nvt"}.get(s, "st-open")


def write_html(path: Path, summary, results):
    env = Environment(loader=FileSystemLoader(TPL), autoescape=select_autoescape(["html", "j2"]))
    env.globals["statusclass"] = statusclass
    domains = []
    for c, r in results:
        if not domains or domains[-1][0] != c["domein"]:
            domains.append((c["domein"], []))
        domains[-1][1].append((c, r))
    top = [(c, f) for c, r in results for f in r.findings if f.ernst in ("Kritiek", "Hoog")]
    top.sort(key=lambda x: (-ERNST_ORDE[x[1].ernst], x[1].bevestigen, x[0]["id"]))
    html = env.get_template("rapport.html.j2").render(s=summary, results=results, domains=domains, top=top)
    path.write_text(html, encoding="utf-8")


def write_json(path: Path, data):
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
