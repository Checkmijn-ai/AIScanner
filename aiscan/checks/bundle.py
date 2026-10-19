"""Frontend-bundel: geen geheimen of interne adressen (U-01), geen source maps in productie (U-02)."""
from __future__ import annotations

import re

from . import check
from ..core import Finding, Result, mask, snippet, redact
from ..secretscan import scan_text, nice

PUBLIC_ENV = re.compile(r"\b((?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC|GATSBY)_[A-Z0-9_]*"
                        r"(?:SECRET|PRIVATE|PASSWORD|PASSWD|SERVICE_ROLE|ADMIN|OPENAI|ANTHROPIC|SK_|DB_|DATABASE)[A-Z0-9_]*)\b")
BROWSER_AI = re.compile(r"dangerouslyAllowBrowser\s*:\s*true|anthropic-dangerous-direct-browser-access")
INTERNAL = re.compile(r"""['"`](https?://(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|"""
                      r"""[a-z0-9.-]+\.(?:internal|local|corp|lan)|localhost:\d+)[^'"`]*)['"`]""")
SOURCEMAP_CFG = [
    (re.compile(r"productionBrowserSourceMaps\s*:\s*true"), "next.config"),
    (re.compile(r"sourcemap\s*:\s*(true|['\"]inline['\"])"), "vite/rollup"),
    (re.compile(r"productionSourceMap\s*:\s*true"), "vue.config"),
    (re.compile(r"GENERATE_SOURCEMAP\s*=\s*true"), "create-react-app"),
]


def _is_web(proj):
    return any(p.suffix in (".jsx", ".tsx", ".vue", ".svelte", ".html") for p in proj.files) or bool(proj.build_files)


@check("U-01")
def bundle_secrets(proj, meta):
    r = Result("U-01")
    if not _is_web(proj):
        r.status, r.reden = "Niet van toepassing", "Geen webclient gevonden."
        return r
    js = [p for p in proj.build_files if p.suffix in (".js", ".mjs", ".map", ".html", ".json")]
    for p in js:
        rel = proj.rel(p)
        text = proj.text(p)
        for ln, rid, desc, secret, line in scan_text(text, rel)[:20]:
            r.add(Finding("U-01", meta["ernst"], f"Geheim in de gebouwde frontend: {nice(rid)}", rel, ln,
                          redact(line, secret)[:120]))
        for m in list(INTERNAL.finditer(text))[:3]:
            r.add(Finding("U-01", "Laag", "Intern adres in de gebouwde frontend", rel, bewijs=m.group(1)[:100], bevestigen=True))
    for p in proj.source_files({".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".env", ".mjs"}) + proj.find(".env*"):
        rel = proj.rel(p)
        for i, line in enumerate(proj.text(p).splitlines(), 1):
            m = PUBLIC_ENV.search(line)
            if m:
                r.add(Finding("U-01", meta["ernst"], f"Geheime variabele wordt naar de browser gestuurd ({m.group(1)})", rel, i,
                              snippet(re.sub(r"=\s*\S+", "=****", line) if p.name.startswith(".env") else line),
                              bevestigen=True))
            if BROWSER_AI.search(line):
                r.add(Finding("U-01", meta["ernst"], "API-sleutel van een AI-dienst wordt in de browser gebruikt", rel, i, snippet(line)))
    r.info.append(f"{len(js)} gebouwde bestanden en de frontendbroncode doorzocht." if js else
                  "Geen gebouwde frontend in de map gevonden; alleen de broncode is doorzocht. "
                  "Draai de scanner na de build voor een volledig beeld.")
    return r


@check("U-02")
def source_maps(proj, meta):
    r = Result("U-02")
    if not _is_web(proj):
        r.status, r.reden = "Niet van toepassing", "Geen webclient gevonden."
        return r
    maps = [p for p in proj.build_files if p.suffix == ".map"]
    if maps:
        r.add(Finding("U-02", meta["ernst"], f"{len(maps)} source maps in de gebouwde uitvoer", proj.rel(maps[0]),
                      bewijs="Met source maps is de volledige broncode van de frontend leesbaar voor iedereen."))
    for p in proj.files:
        if re.search(r"(next|vite|vue|webpack|rollup)\.config\.|\.env\.production$|\.env$", p.name):
            for i, line in enumerate(proj.text(p).splitlines(), 1):
                for rx, what in SOURCEMAP_CFG:
                    if rx.search(line):
                        r.add(Finding("U-02", meta["ernst"], f"Source maps aan in de productiebuild ({what})", proj.rel(p), i, snippet(line)))
    return r
