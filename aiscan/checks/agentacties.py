"""Agents die zelf handelen: actiecontrole (H-29) en een sandbox voor code die een agent uitvoert (H-31).

Wat de scan bekijkt, met vaste regels:
- of er een agent in de code zit (LangChain, LangGraph, OpenAI Agents, CrewAI, AutoGen, LlamaIndex, Pydantic AI,
  smolagents, Mastra, de AI SDK van Vercel, function calling van OpenAI of Anthropic, een eigen MCP-server);
- welke tools die agent krijgt, en wat die tools doen: shell of code uitvoeren, betalen, mailen, verwijderen, schrijven;
- of er bij tools met gevolgen een bevestigingsstap in de code staat (needsApproval, interrupt, requires_approval ...);
- of code die een agent uitvoert, in een sandbox draait (Docker, E2B, een gehoste code-interpreter).

Bevestiging en sandbox kunnen ook buiten de code geregeld zijn. Bevindingen zonder harde aanwijzing zijn daarom
"na te kijken" en tellen niet mee in de score; een tool die rechtstreeks shell of code uitvoert zonder sandbox wel.
"""
from __future__ import annotations

import re

from . import check
from .code import JS, PY, TEST_PATH, COMMENT
from ..core import Finding, Result, snippet, is_vendored

I = re.I
AGENT = re.compile(
    r"(\bAgentExecutor\b|create_react_agent|create_tool_calling_agent|create_openai_tools_agent|initialize_agent|"
    r"\bStateGraph\b|from\s+agents\s+import|@function_tool|['\"]@openai/agents['\"]|from\s+crewai\s+import|"
    r"\bautogen\b|AssistantAgent|ConversableAgent|\bReActAgent\b|\bFunctionAgent\b|from\s+pydantic_ai\s+import|"
    r"from\s+smolagents\s+import|\bCodeAgent\b|\bToolCallingAgent\b|['\"]@mastra/core|['\"]@modelcontextprotocol/sdk|"
    r"from\s+mcp\.server|\bFastMCP\b|\btool_calls\b|\btool_use\b|\bbindTools\b|\.bind_tools\(|\btools\s*:\s*\{|"
    r"\bmaxSteps\b|\bstopWhen\b)")
TOOLDEF_PY = re.compile(r"^\s*@(tool|function_tool|\w+\.tool|\w+\.agent\.tool|agent\.tool_plain|agent\.tool)\b(\(.*\))?\s*$")
TOOLDEF_JS = re.compile(r"(\btool\(\s*\{|\.tool\(\s*['\"`]|\bregisterTool\(|new\s+Dynamic(Structured)?Tool\(|createTool\(\s*\{|"
                        r"\bStructuredTool\.from_function\(|FunctionTool\.from_defaults\()")

# Wat een tool doet. Volgorde = belang.
EFFECTEN = [
    ("shell", re.compile(r"(\bsubprocess\.|\bos\.system\(|\bos\.popen\(|child_process|\bexecSync\(|\bexecFile\(|\bspawn\(|"
                         r"\bshell=True|\bexeca\(|\$`)")),
    ("code", re.compile(r"(\beval\(|\bexec\(|new Function\(|\bvm\.run|runInNewContext|PythonREPL|compile\([^)]*['\"]exec['\"])")),
    ("betalen", re.compile(r"(stripe\.(charges|paymentIntents|payment_intents|transfers|refunds|payouts|PaymentIntent|Charge|"
                           r"Transfer|Refund|Payout)\.?(create|Create)|mollie[\w.]*payments\.create|paypal[\w.]*(create|execute)|"
                           r"\.payments\.create\()", I)),
    ("verwijderen", re.compile(r"(\bDELETE\s+FROM\b|\bDROP\s+(TABLE|DATABASE)\b|\bTRUNCATE\b|\.delete\(|\.deleteMany\(|"
                               r"\.destroy\(|\bfs\.(unlink|rm|rmdir)|\bos\.(remove|unlink|rmdir)\(|shutil\.rmtree|rm -rf)", I)),
    ("mailen", re.compile(r"(sendMail\(|send_mail\(|smtplib|\.emails\.send\(|sgMail\.send|nodemailer|postmark|"
                          r"\.messages\.create\([^)]*\bto\b|twilio)", I)),
    ("schrijven", re.compile(r"(\bINSERT\s+INTO\b|\bUPDATE\s+\w+\s+SET\b|\.insert\(|\.upsert\(|prisma\.\w+\.(create|update)|\.from\([^)]*\)\.update\(|"
                             r"\bfs\.writeFile|open\([^)]*['\"]w)", I)),
]
ERNSTIG = {"shell", "code", "betalen", "verwijderen"}
BEVESTIGING = re.compile(r"(needsApproval|needs_approval|requires?_?[aA]pproval|requireApproval|human_in_the_loop|"
                         r"humanInTheLoop|HumanApproval|\binterrupt\(|interrupt_before|interruptBefore|human_input_mode\s*=\s*['\"]ALWAYS|"
                         r"ask_for_confirmation|askForConfirmation|confirmation_required|approval_required|onApproval|"
                         r"tool_approval|approveToolCall|\bapproval\b)", I)
SANDBOX = re.compile(r"(\be2b\b|@e2b/|e2b_code_interpreter|DockerCommandLineCodeExecutor|use_docker\s*=\s*True|"
                     r"executor_type\s*=\s*['\"](e2b|docker|modal|wasm)|code_execution_mode\s*=\s*['\"]safe|"
                     r"code_interpreter|CodeInterpreterTool\(\s*\)|firecracker|gvisor|pyodide|@vercel/sandbox|daytona|"
                     r"\bmodal\.Sandbox|isolated-vm|\bsandbox\b)", I)
# Bekende tools of instellingen die code of shell rechtstreeks op de server uitvoeren.
ONVEILIG = [
    (re.compile(r"\b(PythonREPLTool|PythonAstREPLTool|PythonREPL)\b"), "code",
     "Agent krijgt een Python-tool die code rechtstreeks op de server uitvoert"),
    (re.compile(r"\bShellTool\b|\bBashProcess\b|\bTerminalTool\b"), "shell", "Agent krijgt een shelltool op de server"),
    (re.compile(r"allow_dangerous_code\s*=\s*True"), "code", "Gevaarlijke code-uitvoering expliciet toegestaan (allow_dangerous_code=True)"),
    (re.compile(r"LocalCommandLineCodeExecutor|use_docker\s*=\s*False"), "code",
     "Agent voert code lokaal uit, buiten een container (AutoGen)"),
    (re.compile(r"code_execution_mode\s*=\s*['\"]unsafe"), "code", "Agent voert code uit zonder sandbox (CrewAI, unsafe)"),
    (re.compile(r"\bLocalShellTool\b|\blocal_shell\b"), "shell", "Agent krijgt een lokale shell (OpenAI Agents)"),
    (re.compile(r"executor_type\s*=\s*['\"]local['\"]"), "code", "Agent voert code lokaal uit (smolagents, executor_type=local)"),
]
GEVAARLIJKE_VERZOEKEN = re.compile(r"allow_dangerous_requests\s*=\s*True")


REGEXREGEL = re.compile(r"""(re\.compile\(|^\s*r["']|^\s*\(re\.compile|^\s*\(["'][a-z]+["'],\s*re\.compile|new RegExp\(|^\s*/.*/[gimsuy]*[,;]?\s*$)""")


def _zonder_regex(text):
    """Regels die zelf een zoekpatroon definiëren (zoals in deze scanner) tellen niet als code."""
    return "\n".join("" if REGEXREGEL.search(l) else l for l in text.splitlines())


def _agent_files(proj):
    out = []
    for p in proj.source_files(JS | PY):
        t = proj.text(p)
        if TEST_PATH.search(proj.rel(p)) or is_vendored(p, t):
            continue
        t = _zonder_regex(t)
        tooldef = any(TOOLDEF_PY.match(l) for l in t.splitlines()) if p.suffix == ".py" else bool(TOOLDEF_JS.search(t))
        if AGENT.search(t) or tooldef:
            out.append(p)
    return out


def _tools(proj, p):
    """Tooldefinities in een bestand: lijst van (regel, naam, tekst van de tool)."""
    lines = _zonder_regex(proj.text(p)).splitlines()
    py = p.suffix == ".py"
    starts = []
    for i, line in enumerate(lines):
        if COMMENT.match(line):
            continue
        if (py and TOOLDEF_PY.match(line)) or TOOLDEF_JS.search(line):
            starts.append(i)
    out = []
    for k, s in enumerate(starts):
        e = min(starts[k + 1] if k + 1 < len(starts) else len(lines), s + 45)
        body = lines[s:e]
        if py:  # stop bij de volgende functie of klasse op het hoogste niveau
            for j, line in enumerate(body[2:], 2):
                if line and not line[0].isspace() and not line.startswith((")", "]", "}")):
                    body = body[:j]
                    break
        naam = ""
        for line in body[:4]:
            m = re.search(r"def\s+(\w+)|name\s*:\s*['\"`]([\w-]+)|\.tool\(\s*['\"`]([\w-]+)", line)
            if m:
                naam = next(g for g in m.groups() if g)
                break
        out.append((s + 1, naam or "tool", "\n".join(body)))
    return out


def _effecten(tekst):
    code = "\n".join(l for l in tekst.splitlines() if not COMMENT.match(l))
    return [n for n, rx in EFFECTEN if rx.search(code)]


def _scan(proj):
    """Gedeelde analyse voor H-29 en H-31, één keer per project."""
    if getattr(proj, "_agentscan", None) is not None:
        return proj._agentscan
    files = _agent_files(proj)
    res = {"files": files, "tools": [], "onveilig": [], "verzoeken": [], "losse": []}
    for p in files:
        text = _zonder_regex(proj.text(p))
        rel = proj.rel(p)
        bevestiging = bool(BEVESTIGING.search(text))
        sandbox = bool(SANDBOX.search(text))
        tools = _tools(proj, p)
        for regel, naam, body in tools:
            eff = _effecten(body)
            res["tools"].append({"bestand": rel, "regel": regel, "naam": naam, "effecten": eff,
                                 "bevestiging": bevestiging or bool(BEVESTIGING.search(body)),
                                 "sandbox": sandbox, "bewijs": snippet(body.splitlines()[0])})
        for i, line in enumerate(text.splitlines(), 1):
            if COMMENT.match(line) or re.match(r"\s*(import|from)\s", line):
                continue
            for rx, soort, titel in ONVEILIG:
                if rx.search(line):
                    res["onveilig"].append((rel, i, soort, titel, snippet(line), sandbox))
                    break
            if GEVAARLIJKE_VERZOEKEN.search(line):
                res["verzoeken"].append((rel, i, snippet(line)))
        # function calling zonder herkenbare tooldefinities: gevolgen in hetzelfde bestand als de afhandeling
        if not tools and re.search(r"\btool_calls\b|\btool_use\b|\bfunction_call\b", text):
            eff = _effecten(text)
            if eff:
                res["losse"].append({"bestand": rel, "effecten": eff, "bevestiging": bevestiging, "sandbox": sandbox})
    proj._agentscan = res
    return res


def _lijst(eff):
    return ", ".join(eff[:-1]) + (" en " if len(eff) > 1 else "") + eff[-1]


@check("H-29")
def agent_acties(proj, meta):
    r = Result("H-29")
    s = _scan(proj)
    if not s["files"]:
        r.status, r.reden = "Niet van toepassing", "Geen agent of tools voor een AI-model in de code gevonden."
        return r
    met = [t for t in s["tools"] if t["effecten"]]
    r.info.append(f"Agentcode in {len(s['files'])} bestand(en); {len(s['tools'])} tooldefinitie(s) gevonden, "
                  f"waarvan {len(met)} met gevolgen buiten het model.")
    if met:
        r.info.append("Tools met gevolgen: " + "; ".join(f"{t['naam']} ({_lijst(t['effecten'])}) in {t['bestand']}:{t['regel']}"
                                                          for t in met[:12]) + (" ..." if len(met) > 12 else ""))
    for t in met:
        ernstig = [e for e in t["effecten"] if e in ERNSTIG - {"shell", "code"}]
        if t["bevestiging"]:
            continue
        if ernstig:
            r.add(Finding("H-29", "Hoog", f"Agent kan {_lijst(ernstig)} zonder zichtbare bevestiging door een mens",
                          t["bestand"], t["regel"],
                          f"{t['bewijs']}  [tool '{t['naam']}': {_lijst(t['effecten'])}]", bevestigen=True))
        elif {"mailen", "schrijven"} & set(t["effecten"]):
            r.add(Finding("H-29", "Middel", f"Agent kan {_lijst([e for e in t['effecten'] if e in ('mailen', 'schrijven')])} "
                          "zonder zichtbare controle of bevestiging", t["bestand"], t["regel"],
                          f"{t['bewijs']}  [tool '{t['naam']}']", bevestigen=True))
    for x in s["losse"]:
        ernstig = [e for e in x["effecten"] if e in ("betalen", "verwijderen")]
        if ernstig and not x["bevestiging"]:
            r.add(Finding("H-29", "Middel", f"Afhandeling van toolaanroepen kan {_lijst(ernstig)}; geen bevestigingsstap gevonden",
                          x["bestand"], 0, "Ga na of elke toolaanroep in de code gecontroleerd wordt voor ze uitgevoerd wordt.",
                          bevestigen=True))
    for rel, i, line in s["verzoeken"]:
        r.add(Finding("H-29", "Hoog", "Agent mag willekeurige webverzoeken doen (allow_dangerous_requests=True)", rel, i, line,
                      bevestigen=True))
    return r


@check("H-31")
def agent_sandbox(proj, meta):
    r = Result("H-31")
    s = _scan(proj)
    if not s["files"]:
        r.status, r.reden = "Niet van toepassing", "Geen agent of tools voor een AI-model in de code gevonden."
        return r
    uitvoer = [t for t in s["tools"] if {"shell", "code"} & set(t["effecten"])]
    if not uitvoer and not s["onveilig"]:
        r.status, r.reden = "Niet van toepassing", "Geen tool gevonden waarmee een agent code of shellcommando's uitvoert."
        return r
    for rel, i, soort, titel, line, sandbox in s["onveilig"]:
        r.add(Finding("H-31", "Hoog" if not sandbox else "Middel", titel, rel, i, line, bevestigen=sandbox))
    for t in uitvoer:
        if t["sandbox"]:
            if t["sandbox"]:
                r.info.append(f"Tool '{t['naam']}' in {t['bestand']} voert {_lijst([e for e in t['effecten'] if e in ('shell', 'code')])} "
                              "uit; in hetzelfde bestand staat een sandbox.")
            continue
        soort = _lijst([e for e in t["effecten"] if e in ("shell", "code")])
        r.add(Finding("H-31", "Hoog", f"Tool van een agent voert {soort} uit op de server, zonder sandbox", t["bestand"], t["regel"],
                      f"{t['bewijs']}  [tool '{t['naam']}']"))
    r.info.append("Gezocht naar tools die shell of code uitvoeren, en naar een sandbox (Docker, E2B, een gehoste "
                  "code-interpreter) in hetzelfde bestand.")
    return r
