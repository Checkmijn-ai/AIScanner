"""Agentconfiguratie in de repository (B-05) en AI-gebruik in het product (A-09)."""
from __future__ import annotations

import json
import re

from . import check
from .supply import ref
from ..core import Finding, Result, mask, snippet, redact
from ..deps import all_components, norm_py, pnaam
from ..secretscan import scan_text, nice

AGENT_FILES = ("CLAUDE.md", "CLAUDE.local.md", ".claude/*", "AGENTS.md", "GEMINI.md", ".gemini/*", ".cursorrules",
               ".cursor/*", ".cursor/rules/*", ".github/copilot-instructions.md", ".github/instructions/*",
               ".github/prompts/*", ".windsurfrules", ".windsurf/*", ".clinerules", ".clinerules/*", ".roo/*",
               ".roomodes", ".continue/*", ".aider*", ".mcp.json", "mcp.json", ".vscode/mcp.json", ".amazonq/*",
               ".junie/*", "*.prompt.md", ".kiro/*")

UNSAFE = [
    (r"(?i)\b(skip|disable|turn off|don'?t run|do not run|ignore|comment out)\b.{0,30}\btests?\b", "Instructie om tests over te slaan of uit te schakelen"),
    (r"(?i)\b(sla|schakel)\b.{0,20}\btests?\b.{0,20}\b(over|uit)\b", "Instructie om tests over te slaan of uit te schakelen"),
    (r"(?i)--no-verify\b", "Instructie om controles bij commit of push over te slaan (--no-verify)"),
    (r"(?i)\b(ignore|suppress|silence)\b.{0,20}\b(lint|type|typescript|eslint|mypy)\b.{0,10}(errors?|warnings?)", "Instructie om lint- of typefouten te negeren"),
    (r"(?i)(@ts-ignore|eslint-disable|# ?type: ?ignore|noqa)\b.{0,40}\b(always|everywhere|freely|when needed|whenever)", "Instructie om foutmeldingen breed te onderdrukken"),
    (r"(?i)\b(never|don'?t|do not)\b.{0,15}\bask\b.{0,30}\b(permission|confirmation|approval)", "Agent mag handelen zonder bevestiging"),
    (r"(?i)(dangerously-skip-permissions|bypassPermissions|--yolo\b|auto[-_ ]?approve|autoApprove)", "Agent draait zonder goedkeuring van acties"),
    (r"(?i)\b(push|commit|merge)\b.{0,25}\b(directly|straight)\b.{0,15}\b(to )?(main|master|production|prod)\b", "Instructie om rechtstreeks naar de hoofdbranch of productie te gaan"),
    (r"(?i)\bforce[- ]?push\b|push --force|push -f\b", "Instructie om geforceerd te pushen"),
    (r"(?i)\b(disable|skip|turn off)\b.{0,25}\b(ssl|tls|certificate)\b.{0,15}\b(verification|check|validation)", "Instructie om certificaatcontrole uit te schakelen"),
    (r"(?i)\bhard[- ]?code\b.{0,25}\b(api[ _-]?key|password|secret|token|credential)", "Instructie om geheimen in de code te zetten"),
    (r"(?i)\b(skip|ignore|bypass|disable)\b.{0,20}\b(security|auth|authentication|authorization|csrf|validation)\b.{0,20}\b(checks?|for now|to make it work)", "Instructie om beveiliging over te slaan"),
    (r"(?i)\b(commit|add)\b.{0,15}\.env\b", "Instructie om .env mee te committen"),
    (r"(?i)\b(rm -rf|drop table|delete from)\b.{0,40}\b(without|no)\b.{0,10}\b(asking|confirm)", "Destructieve actie zonder bevestiging"),
]
UNSAFE_RX = [(re.compile(p), t) for p, t in UNSAFE]
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@(?!example\.|test\.|users\.noreply\.github\.com|anthropic\.com|localhost)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def agent_files(proj):
    return proj.find(*AGENT_FILES, where="all_files")


@check("B-05")
def agent_config(proj, meta):
    r = Result("B-05")
    files = [p for p in agent_files(proj) if p.is_file()]
    if not files:
        r.status, r.reden = "Niet van toepassing", "Geen agentconfiguratie of instructiebestanden voor AI-assistenten gevonden."
        return r
    r.info.append("Bekeken: " + ", ".join(sorted(proj.rel(p) for p in files))[:600])
    for p in files:
        rel, text = proj.rel(p), proj.text(p)
        for ln, rid, desc, secret, line in scan_text(text, rel):
            r.add(Finding("B-05", "Kritiek", f"Geheim in agentconfiguratie: {nice(rid)}", rel, ln,
                          redact(line, secret)))
        for i, line in enumerate(text.splitlines() if not p.name.endswith(".json") else [], 1):
            for rx, title in UNSAFE_RX:
                if rx.search(line):
                    r.add(Finding("B-05", meta["ernst"], title, rel, i, snippet(line), bevestigen=True))
                    break
        mails = {m.group(0) for m in EMAIL.finditer(text)}
        if len(mails) >= 3:
            r.add(Finding("B-05", "Middel", f"Mogelijke persoonsgegevens in agentbestand ({len(mails)} e-mailadressen)", rel,
                          bewijs="Voorbeeld: " + mask(sorted(mails)[0]), bevestigen=True))
        if p.name.endswith(".json"):
            d = proj.json(p) or {}
            servers = d.get("mcpServers") or d.get("servers") or {}
            for name, s in (servers.items() if isinstance(servers, dict) else []):
                if not isinstance(s, dict):
                    continue
                args = " ".join(map(str, s.get("args", [])))
                cmd = f"{s.get('command', '')} {args}"
                if re.search(r"\bnpx\b", cmd):
                    pkgs = [a for a in s.get("args", []) if isinstance(a, str) and not a.startswith("-")]
                    if pkgs and "@" not in pkgs[0].lstrip("@"):
                        r.add(Finding("B-05", "Middel", f"MCP-server '{name}' draait een pakket zonder vaste versie", rel,
                                      bewijs=snippet(cmd), bevestigen=True))
                if str(s.get("url", "")).startswith("http://") and "localhost" not in str(s.get("url")):
                    r.add(Finding("B-05", "Middel", f"MCP-server '{name}' via onversleutelde verbinding", rel, bewijs=s.get("url")))
                if s.get("autoApprove") in (["*"], True) or s.get("alwaysAllow") in (["*"], True):
                    r.add(Finding("B-05", "Hoog", f"MCP-server '{name}': alle acties automatisch goedgekeurd", rel))
            perms = (d.get("permissions") or {}) if isinstance(d, dict) else {}
            allow = perms.get("allow") or []
            if perms.get("defaultMode") == "bypassPermissions" or any(a in ("Bash(*)", "Bash", "*") for a in allow):
                r.add(Finding("B-05", "Hoog", "Agent mag elke shellopdracht uitvoeren zonder bevestiging", rel,
                              bewijs=json.dumps(perms)[:200]))
    return r


AI_CODE = re.compile(r"(api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|openai\.azure\.com|"
                     r"api\.mistral\.ai|api\.groq\.com|bedrock-runtime|/v1/chat/completions|/v1/messages\b)")
AI_TOOLS = re.compile(r"(tool_choice|function_call|\btools\s*[=:]\s*\[|AgentExecutor|create_react_agent|"
                      r"@modelcontextprotocol/sdk|from mcp |StateGraph|crewai|autogen)")


@check("A-09")
def ai_usage(proj, meta):
    r = Result("A-09")
    pk = {k: set(v) for k, v in ref()["ai_pakketten"].items()}
    pkgs = sorted({c.name for c in all_components(proj) if c.direct and
                   (pnaam(c) in pk.get(c.ecosystem, set()))})
    endpoints, tools = set(), set()
    for p in proj.source_files({".js", ".jsx", ".ts", ".tsx", ".mjs", ".py", ".rb", ".php", ".java", ".kt", ".go", ".cs"}):
        t = proj.text(p)
        for m in AI_CODE.finditer(t):
            endpoints.add(m.group(1))
        if AI_TOOLS.search(t):
            tools.add(proj.rel(p))
    uses = bool(pkgs or endpoints)
    proj.ai = {"gebruikt": uses, "pakketten": pkgs, "endpoints": sorted(endpoints), "tools": sorted(tools)[:10]}
    if uses:
        r.info.append("AI: ja. Aanwijzingen: " + ", ".join(pkgs + sorted(endpoints)))
        if tools:
            r.info.append("Het product laat een model tools of acties aanroepen (in " + ", ".join(sorted(tools)[:5]) +
                          "): autonomieniveau minstens AI-2; de bouwer bevestigt het niveau in de verklaring.")
        else:
            r.info.append("Geen tool- of agentaanroepen gevonden: vermoedelijk AI-1 (het model helpt, een mens beslist); "
                          "de bouwer bevestigt dit in de verklaring.")
    else:
        r.info.append("AI: nee. Geen AI-pakketten of aanroepen van AI-diensten gevonden; de bouwer bevestigt dit in de verklaring.")
    return r
