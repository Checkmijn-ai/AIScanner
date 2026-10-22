"""MCP-server voor aiscan: agents (Claude Code, Cursor, VS Code Copilot, Windsurf …) roepen de scan aan.

- Draait lokaal via stdio (JSON-RPC 2.0, één bericht per regel). Geen extra pakketten nodig.
- Het netwerk is in dit proces geblokkeerd: elke poging tot een verbinding faalt. De code kan dit proces dus niet
  verlaten. Alleen het rapport komt in de map .aiscan van het project, en jij beslist of je het deelt.
- De scan zelf werkt met vaste regels, zonder AI: dezelfde code geeft dezelfde uitkomst.

Starten: python -m aiscan.mcp_server
"""
from __future__ import annotations

import json
import socket
import sys
import time
import traceback
from pathlib import Path

from . import __version__

PROTOCOL = "2025-06-18"
SUPPORTED = {"2024-11-05", "2025-03-26", "2025-06-18"}


# ------------------------------------------------------------------ netwerk blokkeren
class NetwerkGeblokkeerd(PermissionError):
    pass


def _blok(*a, **k):
    raise NetwerkGeblokkeerd("aiscan: netwerk is geblokkeerd in de MCP-server; er wordt niets verstuurd")


def blokkeer_netwerk():
    socket.socket.connect = _blok
    socket.socket.connect_ex = _blok
    socket.socket.sendto = _blok
    socket.create_connection = _blok
    socket.getaddrinfo = _blok


def netwerk_is_dicht() -> bool:
    try:
        socket.create_connection(("example.com", 443), timeout=1)
        return False
    except NetwerkGeblokkeerd:
        return True
    except Exception:
        return False


# ------------------------------------------------------------------ scan
_LAATSTE: dict = {}

TOOLS = [
    {
        "name": "aiscan_scan",
        "title": "AI-code scan",
        "description": ("Scant een codeproject lokaal op 45 controles voor software die met AI gebouwd is (geheimen, kwetsbare en "
                        "verzonnen pakketten, injectie, agentconfiguratie, frontendrisico's …), elk gekoppeld aan een norm of wet. "
                        "Geeft de scanscore A–G, de belangrijkste bevindingen met bestand en regel, en een herstelhint per scan. "
                        "Het netwerk is geblokkeerd: er verlaat geen code de machine. Het rapport (HTML en JSON) komt in .aiscan/ "
                        "in het project. Gebruik dit na het schrijven of wijzigen van code, en opnieuw na het herstellen."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "pad": {"type": "string", "description": "Absoluut pad naar de projectmap (standaard: de huidige map)"},
                "alleen": {"type": "array", "items": {"type": "string"},
                           "description": "Alleen deze scan-ID's draaien, bv. [\"E-05\", \"F-01\"]"},
                "max_bevindingen": {"type": "integer", "description": "Maximum aantal bevindingen in het antwoord (standaard 30)"},
                "nonce": {"type": "string", "description": "Sessiecode van de API; dan schrijft de scan ook .aiscan/bewijs.json"},
            },
        },
        "annotations": {"title": "AI-code scan", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,
                        "openWorldHint": False},
    },
    {
        "name": "aiscan_details",
        "title": "Details van één scan",
        "description": "Alle bevindingen van één scan uit de laatste aiscan_scan, met normen, uitleg en herstelhint.",
        "inputSchema": {"type": "object", "properties": {"scan_id": {"type": "string", "description": "bv. E-04"}},
                        "required": ["scan_id"]},
        "annotations": {"title": "Details van één scan", "readOnlyHint": True, "openWorldHint": False},
    },
]


def _loc(f):
    return f"{f.bestand}{':' + str(f.regel) if f.regel else ''}" if f.bestand else "project"


def tool_scan(args):
    from .checks.supply import write_sbom
    from .core import ERNST_ORDE
    from .report import write_html, write_json
    from .runner import run, summarize, to_json

    pad = Path(args.get("pad") or ".").expanduser().resolve()
    if not pad.is_dir():
        return f"Map niet gevonden: {pad}", True, None
    out = pad / ".aiscan"
    out.mkdir(exist_ok=True)
    (out / ".gitignore").write_text("*\n")
    t0 = time.time()
    only = set(args["alleen"]) if args.get("alleen") else None
    proj, results = run(str(pad), 1, offline=True, only=only, log=lambda *a, **k: None)
    write_sbom(proj, out / "sbom.json", pad.name)
    summary = summarize(proj, results, {"klant": "—", "app": pad.name, "versie": "", "niveau": 1,
                                        "scope": f"broncode in {pad.name}; lokaal, zonder netwerk", "uitvoerder": "aiscan via MCP",
                                        "soort": "Zelfscan"})
    write_json(out / "rapport.json", to_json(summary, results))
    write_html(out / "rapport.html", summary, results)
    if args.get("nonce"):
        from .bewijs import maak
        write_json(out / "bewijs.json", maak(proj, results, summary, args["nonce"]))
    _LAATSTE.clear()
    _LAATSTE.update({"pad": str(pad), "results": results, "summary": summary})

    sc = summary["score"]
    alle = [(c, f) for c, r in results for f in r.findings]
    alle.sort(key=lambda x: (-ERNST_ORDE.get(x[1].ernst, 0), x[1].bevestigen, x[0]["id"]))
    n = int(args.get("max_bevindingen") or 30)
    lines = [
        f"# aiscan — {pad.name}",
        f"Scanscore: **{sc['letter'] or 'geen (te weinig gescand)'}** (zelfscan, niveau 1, {sc.get('dekking_tekst', '')}; hoogstens C, een keuring gaat tot A). {sc['uitleg']}",
        f"Bevindingen: {summary['ernst']['Kritiek']} kritiek, {summary['ernst']['Hoog']} hoog, {summary['ernst']['Middel']} middel, "
        f"{summary['ernst']['Laag']} laag · {summary['status']['Geen bevinding']} scans zonder bevinding, {summary['status']['Bevinding']} met bevinding, "
        f"{summary['status']['Niet gescand']} niet gescand, {summary['status']['Niet van toepassing']} niet van toepassing.",
        f"Privacy: lokaal gescand in {time.time() - t0:.1f} s; netwerk geblokkeerd ({'bevestigd' if netwerk_is_dicht() else 'NIET bevestigd'}); "
        f"er is niets verstuurd. Geheimen staan gemaskeerd.",
        f"Rapport: {out / 'rapport.html'} · gegevens: {out / 'rapport.json'}"
        + (f" · bewijs: {out / 'bewijs.json'}" if args.get("nonce") else ""),
        "",
        "## Belangrijkste bevindingen",
    ]
    seen_hint = set()
    for c, f in alle[:n]:
        conf = " (te bevestigen)" if f.bevestigen else ""
        lines.append(f"- [{f.ernst}] {c['id']} {f.titel}{conf} — {_loc(f)}" + (f"\n  bewijs: {f.bewijs}" if f.bewijs else ""))
        if c["id"] not in seen_hint:
            seen_hint.add(c["id"])
            lines.append(f"  herstel: {c.get('hint', '')}")
    if len(alle) > n:
        lines.append(f"- … en nog {len(alle) - n} bevindingen; vraag details per scan met aiscan_details.")
    if not alle:
        lines.append("- Geen bevindingen.")
    open_scans = [f"{c['id']} ({r.reden})" for c, r in results if r.status == "Niet gescand"]
    if open_scans:
        lines += ["", "## Niet gescand", *[f"- {x}" for x in open_scans[:12]]]
    lines += ["", "Werkwijze: herstel de kritieke en hoge bevindingen, en draai aiscan_scan opnieuw om de score te zien stijgen. "
                  "Deze score is een zelfscan (hoogstens C), geen keurmerk of certificaat."]
    structured = {"score": sc["letter"], "dekking": sc["dekking"], "ernst": summary["ernst"], "status": summary["status"],
                  "rapport_html": str(out / "rapport.html"), "rapport_json": str(out / "rapport.json")}
    return "\n".join(lines), False, structured


def tool_details(args):
    sid = (args.get("scan_id") or "").upper().strip()
    if not _LAATSTE:
        return "Nog geen scan in deze sessie: roep eerst aiscan_scan aan.", True, None
    for c, r in _LAATSTE["results"]:
        if c["id"] == sid:
            lines = [f"# {c['id']} — {c['scan']}", f"Normen en wetten: {c['normen']}", f"Status: {r.status}"
                     + (f" ({r.reden})" if r.reden else ""), f"Herstel: {c.get('hint', '')}", ""]
            for f in r.findings:
                lines.append(f"- [{f.ernst}] {f.titel}{' (te bevestigen)' if f.bevestigen else ''} — {_loc(f)}"
                             + (f"\n  bewijs: {f.bewijs}" if f.bewijs else ""))
            if not r.findings:
                lines.append("Geen bevindingen.")
            lines += [f"Info: {i}" for i in r.info if not i.startswith("Traceback")]
            return "\n".join(lines), False, None
    return f"Onbekende scan-ID: {sid}", True, None


HANDLERS = {"aiscan_scan": tool_scan, "aiscan_details": tool_details}


# ------------------------------------------------------------------ JSON-RPC
def respond(msg_id, result=None, error=None):
    out = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        out["error"] = error
    else:
        out["result"] = result
    sys.stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def handle(msg):
    method, mid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    if mid is None:  # notificatie
        return
    if method == "initialize":
        pv = params.get("protocolVersion")
        respond(mid, {
            "protocolVersion": pv if pv in SUPPORTED else PROTOCOL,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "aiscan", "title": "AI-code scan", "version": __version__},
            "instructions": ("Gebruik aiscan_scan na het schrijven of wijzigen van code om fouten te vinden die typisch zijn voor "
                             "code van AI. Het netwerk is geblokkeerd: er verlaat geen code de machine. Herstel kritieke en hoge "
                             "bevindingen en scan opnieuw."),
        })
    elif method == "ping":
        respond(mid, {})
    elif method == "tools/list":
        respond(mid, {"tools": TOOLS})
    elif method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        fn = HANDLERS.get(name)
        if not fn:
            respond(mid, error={"code": -32602, "message": f"Onbekende tool: {name}"})
            return
        try:
            text, is_err, structured = fn(args)
        except Exception as e:
            text, is_err, structured = f"Fout in aiscan: {type(e).__name__}: {e}\n{traceback.format_exc(limit=3)}", True, None
        res = {"content": [{"type": "text", "text": text}], "isError": is_err}
        if structured is not None:
            res["structuredContent"] = structured
        respond(mid, res)
    else:
        respond(mid, error={"code": -32601, "message": f"Methode niet ondersteund: {method}"})


def main():
    blokkeer_netwerk()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            respond(None, error={"code": -32700, "message": "Ongeldige JSON"})
            continue
        for m in (msg if isinstance(msg, list) else [msg]):
            handle(m)


if __name__ == "__main__":
    main()
