"""Regels op de broncode (JavaScript/TypeScript en Python).

Elke regel is een vast patroon. Wat een patroon niet zeker kan vaststellen, staat als 'te bevestigen'
in het rapport: de scan markeert, een analist bevestigt (niveau 2).
"""
from __future__ import annotations

import re
from collections import defaultdict

from . import check
from ..core import Finding, Result, snippet, is_vendored

JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}
PY = {".py"}
TPL = {".html", ".htm", ".jinja", ".jinja2", ".j2", ".ejs", ".hbs", ".njk"}
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|e2e|cypress|fixtures?|mocks?|__mocks__|examples?|docs?)(/|$)|"
                       r"\.(test|spec|stories)\.[a-z]+$|(^|/)test_[^/]*\.py$|_test\.py$|conftest\.py$")
COMMENT = re.compile(r"^\s*(//|#|\*|/\*|<!--)")
AI_CALL = re.compile(r"(chat\.completions\.create|\bcompletions\.create|\bmessages\.create|\bresponses\.create|\bgenerateText\s*\(|"
                     r"\bstreamText\s*\(|\bgenerateObject\s*\(|\bgenerate_content\s*\(|\bgenerateContent\s*\(|\.invoke\(|\.ainvoke\(|"
                     r"\bChatOpenAI\b|\bChatAnthropic\b|litellm\.completion|ollama\.chat|\bclient\.chat\()")
AI_IMPORT = re.compile(r"""(from\s+['"](openai|@anthropic-ai/sdk|ai|@ai-sdk/[\w-]+|langchain[\w/-]*|@langchain/[\w-]+|@google/genai|"""
                       r"""@google/generative-ai|ollama|groq-sdk|@mistralai/mistralai|cohere-ai)['"]|require\(\s*['"](openai|"""
                       r"""@anthropic-ai/sdk|ai|langchain[\w/-]*|@google/generative-ai|ollama)['"]\s*\)|^\s*(import|from)\s+(openai|anthropic|"""
                       r"""langchain[\w.]*|llama_index|google\.generativeai|google\.genai|ollama|litellm|mistralai|groq|cohere)\b)""", re.M)


class R:
    def __init__(self, check, langs, pattern, ernst, titel, bevestigen=False, flags=0, skip_tests=True,
                 file_needs=None, file_lacks=None, aggregate=False):
        self.check, self.langs, self.ernst, self.titel = check, langs, ernst, titel
        self.rx = re.compile(pattern, flags)
        self.bevestigen, self.skip_tests, self.aggregate = bevestigen, skip_tests, aggregate
        self.file_needs = re.compile(file_needs) if file_needs else None
        self.file_lacks = re.compile(file_lacks) if file_lacks else None


I = re.I
RULES = [
    # ---------------- C-01 gevaarlijke constructies (ISO/IEC 5055: beveiliging en betrouwbaarheid)
    R("C-01", JS, r"\beval\s*\(\s*(?!['\"`][^'\"`]*['\"`]\s*\))", "Hoog", "eval() met een variabele: willekeurige code kan uitgevoerd worden"),
    R("C-01", JS, r"\bnew\s+Function\s*\(", "Hoog", "new Function(): code wordt uit tekst opgebouwd", bevestigen=True),
    R("C-01", JS, r"\b(unserialize|deserialize)\s*\(.*\breq\.", "Kritiek", "Onveilige deserialisatie van invoer van de gebruiker"),
    R("C-01", JS, r"\b(sendFile|readFile|readFileSync|createReadStream|download)\s*\([^)]*\breq\.(params|query|body)", "Hoog",
      "Bestandspad uit invoer van de gebruiker: mogelijk path traversal", bevestigen=True),
    R("C-01", JS, r"noent\s*:\s*true", "Hoog", "XML-parser met externe entiteiten aan (XXE)"),
    R("C-01", PY, r"\bpickle\.loads?\s*\(|\bcPickle\.loads?\s*\(|\bmarshal\.loads\s*\(|\bjsonpickle\.decode\s*\(", "Hoog",
      "Onveilige deserialisatie (pickle, marshal of jsonpickle)", bevestigen=True),
    R("C-01", PY, r"\byaml\.load\s*\((?![^)]*(SafeLoader|CSafeLoader|BaseLoader))", "Hoog", "yaml.load zonder SafeLoader: code kan uitgevoerd worden"),
    R("C-01", PY, r"(?<![\w.])(eval|exec)\s*\(\s*(?!['\"])", "Hoog", "eval() of exec() met een variabele"),
    R("C-01", PY, r"\b(open|send_file|send_from_directory|FileResponse)\s*\([^)]*\brequest\.(args|form|GET|POST|query_params|json)", "Hoog",
      "Bestandspad uit invoer van de gebruiker: mogelijk path traversal", bevestigen=True),
    R("C-01", PY, r"resolve_entities\s*=\s*True|XMLParser\([^)]*load_dtd\s*=\s*True", "Hoog", "XML-parser met externe entiteiten aan (XXE)"),
    R("C-01", PY, r"^\s*assert\b.*\b(is_admin|is_authenticated|permission|authorized|role)\b", "Middel",
      "Beveiligingscontrole met assert: verdwijnt als Python geoptimaliseerd draait"),

    # ---------------- C-06 foutafhandeling
    R("C-06", JS, r"catch\s*(\(\s*\w*\s*\))?\s*\{\s*\}", "Middel", "Lege catch: fouten worden ingeslikt", aggregate=True),
    R("C-06", JS, r"\.catch\s*\(\s*\(\s*\w*\s*\)\s*=>\s*\{\s*\}\s*\)", "Middel", "Lege .catch(): fouten worden ingeslikt", aggregate=True),
    R("C-06", JS, r"\.(send|json|write|end)\s*\([^)]*\b(err|error|e)\.stack\b|res\.(status\(\s*500\s*\)\.)?(send|json)\s*\(\s*(err|error)\s*\)",
      "Hoog", "Foutdetails of stacktrace naar de gebruiker gestuurd", bevestigen=True),
    R("C-06", PY, r"^\s*except\s*(Exception|BaseException)?\s*(as\s+\w+)?\s*:\s*(pass|\.\.\.)\s*$", "Middel",
      "except met pass: fouten worden ingeslikt", aggregate=True),
    R("C-06", PY, r"traceback\.format_exc\(\).*(return|jsonify|Response|HttpResponse)|(return|jsonify|Response)\(.*traceback\.format_exc\(\)",
      "Hoog", "Stacktrace naar de gebruiker gestuurd", bevestigen=True),
    R("C-06", PY, r"\.run\([^)]*debug\s*=\s*True", "Hoog", "Debugmodus aan: gebruikers zien stacktraces en kunnen code uitvoeren",
      bevestigen=True),
    R("C-06", PY, r"^\s*DEBUG\s*=\s*True\b", "Hoog", "DEBUG = True in de instellingen", bevestigen=True),

    # ---------------- C-13 code smells (alleen hoge zekerheid, samengevat per bestand)
    R("C-13", JS, r"\bnew Buffer\s*\(|\bfs\.exists\s*\(|\burl\.parse\s*\(|crypto\.createCipher\s*\(", "Laag",
      "Verouderde (deprecated) API van Node.js", aggregate=True),
    R("C-13", JS | PY, r"""^(?!\s*(//|#|\*)).*['"`]https?://(localhost|127\.0\.0\.1)(:\d+)?[^'"`]*['"`]""", "Laag",
      "Hardgecodeerd adres van localhost in de code", aggregate=True),
    R("C-13", JS | PY, r"(TODO|FIXME|HACK|XXX)\b.*\b(auth|security|password|secret|validat|sanitiz|permission|csrf|token)", "Middel",
      "Open TODO in beveiligingskritieke code", flags=I),
    R("C-13", JS, r"@ts-ignore|eslint-disable(?!-next-line\s+no-console)", "Laag", "Foutmeldingen van TypeScript of ESLint onderdrukt",
      aggregate=True),
    R("C-13", PY, r"datetime\.utcnow\(\)|asyncio\.get_event_loop\(\)|\.warn\(", "Laag", "Verouderde (deprecated) API van Python",
      aggregate=True),

    # ---------------- E-03 sessies
    R("E-03", JS, r"(secure|httpOnly)\s*:\s*false", "Hoog", "Sessiecookie zonder Secure of HttpOnly",
      file_needs=r"(?i)cookie|express-session|cookie-session|session\(", file_lacks=r"createTransport|nodemailer|(?i:smtp)"),
    R("E-03", JS, r"secret\s*:\s*['\"](keyboard cat|secret|changeme|mysecret|supersecret|your[-_ ]?secret)['\"]", "Hoog",
      "Sessiegeheim is een standaardwaarde", flags=I),
    R("E-03", JS, r"jwt\.sign\s*\((?![^)]*expiresIn)[^)]*\)", "Middel", "JWT zonder vervaldatum (expiresIn)", bevestigen=True),
    R("E-03", JS, r"algorithms\s*:\s*\[[^\]]*['\"]none['\"]|ignoreExpiration\s*:\s*true", "Kritiek", "JWT-controle uitgeschakeld"),
    R("E-03", JS, r"jwt\.decode\s*\(", "Middel", "jwt.decode() controleert de handtekening niet; gebruik jwt.verify()", bevestigen=True),
    R("E-03", PY, r"(SESSION_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|CSRF_COOKIE_SECURE)\s*=\s*False", "Hoog", "Sessiecookie zonder Secure of HttpOnly"),
    R("E-03", PY, r"verify_signature['\"]?\s*:\s*False|verify\s*=\s*False\s*\)|algorithms\s*=\s*\[\s*['\"]none['\"]", "Kritiek",
      "JWT-controle uitgeschakeld", file_needs=r"\bjwt\b"),
    R("E-03", PY, r"SECRET_KEY\s*=\s*['\"](secret|changeme|dev|django-insecure-[^'\"]*)['\"]", "Hoog", "Standaard of ontwikkelgeheim als SECRET_KEY",
      flags=I),

    # ---------------- E-04 injectie
    R("E-04", JS, r"\b(query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*`[^`]*\$\{", "Kritiek",
      "SQL opgebouwd met een template string: SQL-injectie", bevestigen=True, file_lacks=r"sql\s*`"),
    R("E-04", JS, r"""\b(query|execute|raw)\s*\(\s*("[^"]*(SELECT|INSERT|UPDATE|DELETE|WHERE)[^"]*"|'[^']*(SELECT|INSERT|UPDATE|DELETE|WHERE)[^']*')\s*\+""", "Kritiek",
      "SQL opgebouwd door tekst aan elkaar te plakken: SQL-injectie", flags=I),
    R("E-04", JS, r"\b(exec|execSync)\s*\(\s*(`[^`]*\$\{|[^'\"`)]+\+|\w+\s*[,)])", "Kritiek", "Shellopdracht met een variabele: commando-injectie",
      bevestigen=True, file_needs=r"child_process"),
    R("E-04", JS, r"\$where|\.find\(\s*req\.(body|query)\s*\)|\.findOne\(\s*req\.(body|query)\s*\)", "Hoog",
      "NoSQL-query rechtstreeks uit invoer van de gebruiker", bevestigen=True),
    R("E-04", JS, r"res\.(send|write)\s*\(\s*`[^`]*<[^`]*\$\{[^}]*req\.", "Hoog", "Invoer van de gebruiker zonder encoding in HTML: XSS"),
    R("E-04", PY, r"\.execute(many)?\s*\(\s*(f['\"]|['\"][^'\"]*['\"]\s*(%|\.format\(|\+))", "Kritiek",
      "SQL opgebouwd met tekstbewerking: SQL-injectie", bevestigen=True),
    R("E-04", PY, r"\b(text|raw|extra)\s*\(\s*f['\"]", "Hoog", "SQL-fragment met een f-string", bevestigen=True),
    R("E-04", PY, r"\bos\.(system|popen)\s*\(\s*(f['\"]|[^'\")]+\+|\w+\s*\))", "Kritiek", "Shellopdracht met een variabele: commando-injectie"),
    R("E-04", PY, r"subprocess\.\w+\([^)]*shell\s*=\s*True", "Hoog", "subprocess met shell=True", bevestigen=True),
    R("E-04", PY, r"render_template_string\s*\(\s*(?!['\"])", "Kritiek", "render_template_string met een variabele: template-injectie"),
    R("E-04", PY, r"Environment\([^)]*autoescape\s*=\s*False|\bMarkup\s*\(\s*(f['\"]|\w+)", "Hoog", "HTML-escaping uitgeschakeld: XSS",
      bevestigen=True),
    R("E-04", TPL, r"\{\{[^}]*\|\s*safe\s*\}\}|\{%\s*autoescape\s+false|<%-", "Middel", "Uitvoer zonder escaping in een template",
      bevestigen=True, aggregate=True),

    # ---------------- E-06 versleuteling
    R("E-06", JS, r"createHash\(\s*['\"](md5|sha1)['\"]\s*\)(?![^\n]*pass)", "Middel", "MD5 of SHA-1: niet geschikt voor beveiliging", bevestigen=True),
    R("E-06", JS, r"(md5|sha1)\s*\([^)]*pass|createHash\(\s*['\"](md5|sha1)['\"]\s*\)\.update\([^)]*pass", "Hoog", "Wachtwoord gehasht met MD5 of SHA-1", flags=I),
    R("E-06", JS, r"createCipheriv?\(\s*['\"](des|des-ede|rc4|bf|aes-\d+-ecb)", "Hoog", "Verouderd of onveilig versleutelingsalgoritme", flags=I),
    R("E-06", JS, r"Math\.random\(\).{0,60}\b(token|secret|password|passwd|key|salt|otp|nonce|session)|\b(token|secret|password|key|salt|otp|nonce)\w*\s*[=:].{0,40}Math\.random\(\)",
      "Hoog", "Math.random() voor een geheim of token: voorspelbaar", flags=I),
    R("E-06", JS, r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0", "Hoog", "Certificaatcontrole van TLS uitgeschakeld"),
    R("E-06", JS | PY, r"""(?<!xmlns=)(?<!xmlns:xsi=)['"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|www\.w3\.org|schemas\.|json-schema\.org|example\.|www\.sitemaps\.org|schema\.org|purl\.org|ns\.adobe\.com|www\.google\.com/schemas|xmlns\.com)[a-z0-9.-]+\.[a-z]{2,}""",
      "Middel", "Onversleutelde verbinding (http://) naar een externe dienst", bevestigen=True, aggregate=True),
    R("E-06", PY, r"hashlib\.(md5|sha1)\s*\([^)]*pass", "Hoog", "Wachtwoord gehasht met MD5 of SHA-1", flags=I),
    R("E-06", PY, r"hashlib\.(md5|sha1)\s*\((?![^\n]*pass)", "Middel", "MD5 of SHA-1: niet geschikt voor beveiliging", bevestigen=True, aggregate=True),
    R("E-06", PY, r"^(?!.*jwt).*\bverify\s*=\s*False", "Hoog", "Certificaatcontrole van TLS uitgeschakeld", file_needs=r"requests|httpx|aiohttp|urllib3"),
    R("E-06", PY, r"ssl\._create_unverified_context|CERT_NONE|check_hostname\s*=\s*False", "Hoog", "Certificaatcontrole van TLS uitgeschakeld"),
    R("E-06", PY, r"\brandom\.(random|randint|choice|choices|getrandbits)\(.{0,60}\b(token|secret|password|key|salt|otp|nonce)|"
                  r"\b(token|secret|password|salt|otp|nonce)\w*\s*=.{0,40}\brandom\.(random|randint|choice|choices)\(",
      "Hoog", "random voor een geheim of token: voorspelbaar; gebruik secrets", flags=I),
    R("E-06", PY, r"DES\.new|ARC4\.new|MODE_ECB|Blowfish\.new", "Hoog", "Verouderd of onveilig versleutelingsalgoritme"),
    R("E-06", JS | PY, r"\b(bcrypt\.(hash|genSalt|gensalt)\w*\s*\([^)]*\b|rounds\s*=\s*)([1-9])\b(?!\d)", "Middel",
      "bcrypt met te weinig rondes (minder dan 10)"),

    # ---------------- U-03 tokens in browseropslag
    R("U-03", JS, r"(localStorage|sessionStorage)\.setItem\s*\(\s*['\"`](?![^'\"`]*(redirect|return|url|slug|path|lang|theme))[^'\"`]*(token|jwt|password|secret|api[_-]?key|credential|(?<![a-z0-9_])session[_-]?id|auth[_-]?(token|key|data)|access[_-]?key)",
      "Hoog", "Token of geheim in localStorage of sessionStorage: leesbaar voor elk script (XSS)", flags=I),
    R("U-03", JS, r"document\.cookie\s*=.*(token|jwt|session|auth)", "Middel", "Token in een cookie vanuit JavaScript: kan niet HttpOnly zijn", flags=I),

    # ---------------- U-07 gevaarlijke DOM-functies
    R("U-07", JS, r"\.(innerHTML|outerHTML)\s*[+]?=(?!=)\s*(?!\s)(?!['\"`][^'\"`$]*['\"`]\s*;?\s*$)", "Hoog", "innerHTML met een variabele: XSS",
      bevestigen=True, file_lacks=r"DOMPurify|sanitize"),
    R("U-07", JS, r"insertAdjacentHTML\s*\(|document\.write\s*\(", "Hoog", "HTML uit tekst in de pagina gezet: XSS", bevestigen=True,
      file_lacks=r"DOMPurify|sanitize"),
    R("U-07", JS, r"dangerouslySetInnerHTML=\{\{\s*__html:\s*(i18n\.|i18next\.)?t\s*\(", "Laag",
      "HTML uit een vertaling: veilig zolang vertalingen niet van gebruikers komen en er geen invoer in wordt ingevuld", bevestigen=True),
    R("U-07", JS, r"^(?!.*application/ld\+json)(?!.*__html:\s*(DOMPurify\.sanitize|(safe|escape|sanitiz|purify)\w*|(i18n\.|i18next\.)?t)\s*\().*dangerouslySetInnerHTML",
      "Hoog", "dangerouslySetInnerHTML zonder sanitisatie: XSS",
      bevestigen=True, file_lacks=r"DOMPurify|sanitize|marked\.parse.*sanitize|const THEMES"),
    R("U-07", JS, r"dangerouslySetInnerHTML=\{\{\s*__html:\s*(safe|escape|sanitiz|purify)\w*\s*\(", "Laag",
      "HTML via een eigen filterfunctie: kijk na dat die functie echt filtert (en getest is)", bevestigen=True,
      file_lacks=r"DOMPurify"),
    R("U-07", JS, r"application/ld\+json.*dangerouslySetInnerHTML|dangerouslySetInnerHTML.*application/ld\+json", "Laag",
      "JSON-LD via dangerouslySetInnerHTML: vervang '<' door '\\u003c' in de JSON", bevestigen=True),
    R("U-07", JS, r"\bv-html\s*=|\{@html\s", "Hoog", "Ruwe HTML in een Vue- of Svelte-template: XSS", bevestigen=True,
      file_lacks=r"DOMPurify|sanitize"),
    R("U-07", JS, r"addEventListener\(\s*['\"]message['\"]", "Hoog", "postMessage-listener zonder controle van de herkomst",
      file_lacks=r"\.origin\b"),
    R("U-07", JS, r"setTimeout\(\s*['\"`]|setInterval\(\s*['\"`]", "Middel", "setTimeout of setInterval met code als tekst"),

    # ---------------- W-03 bestandsopslag
    R("W-03", JS | PY, r"""ACL['"]?\s*[:=]\s*['"]public-read(-write)?['"]|acl\s*=\s*['"]public-read""", "Hoog", "Opslag publiek leesbaar (public-read)"),
    R("W-03", JS | PY, r"""BlockPublic(Acls|Policy)['"]?\s*[:=]\s*(false|False)""", "Hoog", "Publieke toegang tot de bucket niet geblokkeerd"),
    R("W-03", JS, r"multer\(\s*\{[^}]*dest\s*:\s*['\"](\./)?(public|static|www)", "Hoog", "Uploads worden in een publieke map bewaard",
      bevestigen=True),
    R("W-03", PY, r"UPLOAD_FOLDER\s*=\s*['\"][^'\"]*(static|public)", "Hoog", "Uploads worden in een publieke map bewaard", bevestigen=True),
    R("W-03", JS, r"publicAccess\s*:\s*['\"](blob|container)['\"]", "Hoog", "Azure-opslag publiek toegankelijk"),
    R("W-03", JS, r"\.(from|createBucket)\([^)]*\{[^}]*public\s*:\s*true", "Middel", "Publieke opslagbucket", bevestigen=True),

    # ---------------- W-06 limieten
    R("W-06", PY, r"\brequests\.(get|post|put|patch|delete|head|request)\s*\((?![^)]*timeout)", "Middel",
      "Uitgaand verzoek zonder time-out", aggregate=True, bevestigen=True),
    R("W-06", JS, r"limit\s*:\s*['\"](\d{3,}|[5-9]\d)\s*mb['\"]", "Laag", "Zeer hoge limiet op de grootte van verzoeken", flags=I),
    R("W-06", JS, r"multer\(\s*\{(?![^}]*limits)[^}]*\}\s*\)|multer\(\s*\)", "Middel", "Uploads zonder limiet op de bestandsgrootte"),
]

# per check: een korte uitleg van wat de regels bekijken
COVERAGE = {
    "C-01": "eval en new Function, onveilige deserialisatie, path traversal, XXE, assert als beveiliging",
    "C-06": "lege catch en except, stacktraces naar de gebruiker, debugmodus",
    "C-13": "verouderde API's, hardgecodeerde adressen, TODO's in beveiligingscode, onderdrukte foutmeldingen",
    "E-03": "cookie-instellingen, sessiegeheimen, JWT-controle en vervaldatum",
    "E-04": "SQL-, NoSQL-, commando- en template-injectie, XSS aan de serverkant",
    "E-06": "zwakke hashes en algoritmen, voorspelbare random, uitgeschakelde certificaatcontrole, http://",
    "U-03": "tokens in localStorage, sessionStorage en document.cookie",
    "U-07": "innerHTML, dangerouslySetInnerHTML, v-html, document.write, postMessage zonder herkomstcontrole",
    "W-03": "publieke buckets, uploads in publieke mappen",
    "W-06": "time-outs op uitgaande verzoeken, limieten op uploads en verzoekgrootte",
}


def _run_rules(proj):
    if hasattr(proj, "_code_hits"):
        return proj._code_hits
    hits = defaultdict(list)  # check -> [Finding]
    agg = defaultdict(lambda: defaultdict(list))
    files = [p for p in proj.files if p.suffix.lower() in JS | PY | TPL and not p.name.endswith(".min.js")]
    for p in files:
        rel = proj.rel(p)
        is_test = bool(TEST_PATH.search(rel))
        text = proj.text(p)
        if is_vendored(p, text):
            continue
        ext = p.suffix.lower()
        lines = text.splitlines()
        for rule in RULES:
            if ext not in rule.langs or (rule.skip_tests and is_test):
                continue
            if rule.file_needs and not rule.file_needs.search(text):
                continue
            if rule.file_lacks and rule.file_lacks.search(text):
                continue
            n = 0
            for i, line in enumerate(lines, 1):
                if len(line) > 1000 or COMMENT.match(line) and rule.check not in ("C-13",):
                    continue
                if rule.rx.search(line):
                    if rule.aggregate:
                        agg[rule][rel].append((i, line))
                    else:
                        hits[rule.check].append(Finding(rule.check, rule.ernst, rule.titel, rel, i, snippet(line), rule.bevestigen))
                        n += 1
                        if n >= 5:
                            break
    for rule, per_file in agg.items():
        for rel, occ in per_file.items():
            i, line = occ[0]
            more = f" (en nog {len(occ) - 1} keer in dit bestand)" if len(occ) > 1 else ""
            hits[rule.check].append(Finding(rule.check, rule.ernst, rule.titel, rel, i, snippet(line) + more, rule.bevestigen))
    proj._code_hits = (hits, len(files))
    return proj._code_hits


def _generic(cid):
    def fn(proj, meta):
        r = Result(cid)
        langs = proj.languages
        if not langs & {"javascript", "python"}:
            r.status, r.reden = "Niet gescand", "Deze versie heeft regels voor JavaScript/TypeScript en Python."
            return r
        hits, n = _run_rules(proj)
        for f in hits.get(cid, []):
            r.add(f)
        r.info.append(f"{n} bronbestanden bekeken op: {COVERAGE.get(cid, '')}.")
        return r
    return fn


for _cid in ("C-01", "C-06", "C-13", "E-03", "E-04", "E-06", "U-03", "U-07", "W-03", "W-06"):
    check(_cid)(_generic(_cid))


# ---------------- H-02 en H-08: AI in het product
SINKS = re.compile(r"(\beval\s*\(|\bexec\s*\(|new Function\(|\.innerHTML\s*=|dangerouslySetInnerHTML|v-html|child_process|"
                   r"subprocess\.|os\.system|\.execute\s*\(|\.query\s*\(|\$queryRawUnsafe|render_template_string|"
                   r"document\.write|insertAdjacentHTML)")
LIMITS = re.compile(r"(max_tokens|max_output_tokens|maxTokens|maxOutputTokens|max_completion_tokens|maxCompletionTokens)")
RATELIMIT = re.compile(r"(express-rate-limit|rate-limiter-flexible|@upstash/ratelimit|slowapi|flask[_-]limiter|django-ratelimit|"
                       r"django_ratelimit|limits\b|ratelimit|RateLimiter|throttle)", I)


def _ai_files(proj):
    out = []
    for p in proj.source_files(JS | PY):
        t = proj.text(p)
        if TEST_PATH.search(proj.rel(p)) or is_vendored(p, t):
            continue
        if AI_IMPORT.search(t) and AI_CALL.search(t):
            out.append(p)
    return out


AI_OUT = re.compile(r"(choices\[0\]|\.message\.content|\.content\[0\]\.text|output_text|\.output\b|\.text\b|"
                    r"\.generations|response\.content|result\.content|\.completion\b)")
ASSIGN = re.compile(r"(?:const|let|var)?\s*\{?\s*([A-Za-z_]\w*)\s*\}?\s*=\s*(?:await\s+)?([^;\n]+)")


@check("H-02")
def llm_output(proj, meta):
    r = Result("H-02")
    files = _ai_files(proj)
    if not files:
        r.status, r.reden = "Niet van toepassing", "Geen aanroepen van een AI-model in de code gevonden."
        return r
    for p in files:
        lines = proj.text(p).splitlines()
        tainted = set()
        for i, line in enumerate(lines, 1):
            m = ASSIGN.search(line)
            if m and (AI_OUT.search(m.group(2)) or AI_CALL.search(m.group(2)) or any(re.search(r"\b%s\b" % re.escape(t), m.group(2)) for t in tainted)):
                tainted.add(m.group(1))
        tainted -= {"res", "req", "app", "db", "client", "openai", "anthropic", "self", "this"}
        for i, line in enumerate(lines, 1):
            if COMMENT.match(line) or not SINKS.search(line):
                continue
            used = [t for t in tainted if re.search(r"\b%s\b" % re.escape(t), line)]
            if used or AI_OUT.search(line):
                r.add(Finding("H-02", meta["ernst"], "Uitvoer van een AI-model komt ongecontroleerd in een gevaarlijke bewerking",
                              proj.rel(p), i, snippet(line) + (f"  [uitvoer via: {', '.join(sorted(used))}]" if used else "")))
    r.info.append(f"{len(files)} bestanden met aanroepen van een AI-model bekeken; uitvoer van het model gevolgd naar eval, "
                  "shell, SQL en HTML.")
    return r


@check("H-08")
def llm_limits(proj, meta):
    r = Result("H-08")
    files = _ai_files(proj)
    if not files:
        r.status, r.reden = "Niet van toepassing", "Geen aanroepen van een AI-model in de code gevonden."
        return r
    for p in files:
        lines = proj.text(p).splitlines()
        for i, line in enumerate(lines, 1):
            if AI_CALL.search(line) and not COMMENT.match(line):
                window = "\n".join(lines[max(0, i - 3): i + 15])
                if not LIMITS.search(window):
                    r.add(Finding("H-08", meta["ernst"], "Aanroep van een AI-model zonder limiet op het aantal tokens",
                                  proj.rel(p), i, snippet(line), bevestigen=True))
    alltext = "\n".join(proj.text(p) for p in proj.find("package.json", "requirements*.txt", "pyproject.toml")) + \
              "\n".join(proj.text(p) for p in files)
    if not RATELIMIT.search(alltext):
        r.add(Finding("H-08", meta["ernst"], "Geen limiet op het aantal aanvragen (rate limiting) gevonden",
                      bewijs="Zonder limiet kan één gebruiker of aanvaller onbeperkt AI-kosten veroorzaken.", bevestigen=True))
    return r


# ---------------- P-05 webhooks en uitgaande verzoeken
WEBHOOK_ROUTE = re.compile(r"""(\.(post|all|use)\s*\(\s*['"`][^'"`]*webhook|@\w+\.(route|post)\(\s*['"][^'"]*webhook|path\(\s*['"][^'"]*webhook)""", I)
SIGCHECK = re.compile(r"(constructEvent|verifySignature|verify_signature|createHmac|hmac\.|timingSafeEqual|compare_digest|"
                      r"x-hub-signature|stripe-signature|svix|verify_webhook|webhooks\.verify|Webhook\(|validateRequest)", I)
SSRF = re.compile(r"(fetch|axios(\.\w+)?|got|request|http\.get|https\.get)\s*\(\s*(req\.(body|query|params)|request\.(args|form|json|GET|POST))|"
                  r"requests\.(get|post)\s*\(\s*request\.(args|form|json|GET|POST)|urlopen\s*\(\s*request\.")


@check("P-05")
def webhooks(proj, meta):
    r = Result("P-05")
    src = [p for p in proj.source_files(JS | PY) if not TEST_PATH.search(proj.rel(p))]
    n_hooks = 0
    for p in src:
        text = proj.text(p)
        for i, line in enumerate(text.splitlines(), 1):
            if WEBHOOK_ROUTE.search(line):
                n_hooks += 1
                if not SIGCHECK.search(text):
                    r.add(Finding("P-05", meta["ernst"], "Webhook zonder controle van de handtekening", proj.rel(p), i, snippet(line),
                                  bevestigen=True))
            if SSRF.search(line):
                r.add(Finding("P-05", meta["ernst"], "Uitgaand verzoek naar een adres uit invoer van de gebruiker (SSRF)",
                              proj.rel(p), i, snippet(line), bevestigen=True))
    r.info.append(f"{n_hooks} webhook-route(s) gevonden; uitgaande verzoeken nagekeken op adressen uit invoer.")
    return r


# ---------------- U-04 CSRF en clickjacking
@check("U-04")
def csrf_clickjacking(proj, meta):
    r = Result("U-04")
    src = [p for p in proj.source_files(JS | PY) if not TEST_PATH.search(proj.rel(p))]
    alltext = "\n".join(proj.text(p) for p in src)
    deps = "\n".join(proj.text(p) for p in proj.find("package.json", "requirements*.txt", "pyproject.toml", "Pipfile"))
    server_js = re.search(r"require\(['\"]express['\"]\)|from ['\"]express['\"]|fastify|koa", alltext)
    django = "django" in deps.lower()
    flask = re.search(r"\bflask\b", deps, I)
    if not (server_js or django or flask):
        r.status, r.reden = "Niet van toepassing", "Geen eigen webserver (Express, Fastify, Koa, Django, Flask) gevonden."
        return r
    frame = re.search(r"helmet|frame-ancestors|X-Frame-Options|frameguard|XFrameOptionsMiddleware|talisman", alltext + deps, I)
    if not frame:
        r.add(Finding("U-04", meta["ernst"], "Geen bescherming tegen clickjacking (X-Frame-Options of frame-ancestors) gevonden",
                      bevestigen=True, bewijs="Controleer de headers op de live site (E-08)."))
    if django:
        for p in src:
            for i, line in enumerate(proj.text(p).splitlines(), 1):
                if "@csrf_exempt" in line:
                    r.add(Finding("U-04", meta["ernst"], "CSRF-bescherming uitgeschakeld voor deze view", proj.rel(p), i, snippet(line),
                                  bevestigen=True))
                if re.search(r"#\s*['\"]django\.middleware\.csrf\.CsrfViewMiddleware", line):
                    r.add(Finding("U-04", "Hoog", "CSRF-middleware van Django uitgeschakeld", proj.rel(p), i, snippet(line)))
    cookies = re.search(r"express-session|cookie-session|cookie-parser|session\[|flask_login|SESSION_", alltext + deps)
    csrf = re.search(r"csurf|csrf-csrf|lusca|@fastify/csrf|csrf-sync|CSRFProtect|flask_wtf|CsrfViewMiddleware|sameSite\s*:\s*['\"]strict", alltext + deps, I)
    if (server_js or flask) and cookies and not csrf:
        r.add(Finding("U-04", meta["ernst"], "Sessies via cookies zonder CSRF-bescherming", bevestigen=True,
                      bewijs="Geen CSRF-middleware en geen SameSite=Strict gevonden."))
    return r


# ---------------- U-06 scripts van derden
EXT_SCRIPT = re.compile(r"""<script[^>]+src\s*=\s*['"](https?:)?//([^/'"]+)[^'"]*['"][^>]*>""", I)
TRACKERS = re.compile(r"(googletagmanager|google-analytics|gtag\(|fbq\(|connect\.facebook\.net|hotjar|clarity\.ms|"
                      r"static\.hsappstatic|js\.hs-scripts|intercom|segment\.com|mixpanel|tiktok|linkedin\.com/insight|snap\.licdn)", I)
CONSENT = re.compile(r"(cookiebot|onetrust|klaro|cookieconsent|usercentrics|didomi|iubenda|tarteaucitron|consent\s*['\"]?\s*,\s*['\"]default|"
                     r"gtag\(\s*['\"]consent)", I)


@check("U-06")
def third_party(proj, meta):
    r = Result("U-06")
    files = [p for p in proj.files + proj.build_files if p.suffix.lower() in TPL | JS]
    domains, tracker_files = set(), []
    consent = False
    for p in set(files):
        text = proj.text(p)
        for m in EXT_SCRIPT.finditer(text):
            domains.add(m.group(2))
            if "integrity=" not in m.group(0):
                r.add(Finding("U-06", "Laag", f"Script van {m.group(2)} zonder integriteitscontrole (SRI)", proj.rel(p),
                              bewijs=snippet(m.group(0), 140)))
        if TRACKERS.search(text):
            tracker_files.append(proj.rel(p))
        consent = consent or bool(CONSENT.search(text))
    if not files:
        r.status, r.reden = "Niet van toepassing", "Geen webclient gevonden."
        return r
    if tracker_files and not consent:
        r.add(Finding("U-06", meta["ernst"], "Analyse- of trackingscripts zonder toestemmingsbeheer", tracker_files[0], bevestigen=True,
                      bewijs="Gevonden in " + ", ".join(tracker_files[:3])))
    csp = any(re.search(r"Content-Security-Policy|contentSecurityPolicy|helmet\(", proj.text(p)) for p in proj.source_files(JS | PY))
    if domains and not csp:
        r.add(Finding("U-06", "Laag", "Scripts van derden zonder Content Security Policy in de code", bevestigen=True,
                      bewijs="Controleer de CSP-header op de live site (E-08)."))
    r.info.append("Externe scriptdomeinen: " + (", ".join(sorted(domains)) if domains else "geen"))
    return r


# ---------------- S-06 SDK's in mobiele apps
MOBILE_SDK = re.compile(r"(firebase[-/]analytics|@react-native-firebase/analytics|facebook|fbsdk|appsflyer|adjust|amplitude|"
                        r"mixpanel|segment|branch|onesignal|google-mobile-ads|admob|tiktok|appcenter-analytics)", I)
ATT = re.compile(r"(NSUserTrackingUsageDescription|requestTrackingAuthorization|react-native-tracking-transparency|expo-tracking-transparency|"
                 r"consent|UserMessagingPlatform|ump)", I)


@check("S-06")
def mobile_sdks(proj, meta):
    r = Result("S-06")
    if not proj.is_mobile():
        r.status, r.reden = "Niet van toepassing", "Geen mobiele app gevonden."
        return r
    files = proj.find("package.json", "build.gradle", "build.gradle.kts", "Podfile", "pubspec.yaml", "Info.plist")
    sdks = set()
    for p in files:
        for m in MOBILE_SDK.finditer(proj.text(p)):
            sdks.add(m.group(1).lower())
    consent = any(ATT.search(proj.text(p)) for p in proj.files if p.suffix in (".plist", ".json", ".js", ".ts", ".tsx", ".swift", ".kt"))
    r.info.append("SDK's voor analyse of reclame: " + (", ".join(sorted(sdks)) if sdks else "geen gevonden"))
    if sdks and not consent:
        r.add(Finding("S-06", meta["ernst"], "Analyse- of reclame-SDK's zonder toestemmingsvraag gevonden", bevestigen=True,
                      bewijs=", ".join(sorted(sdks))))
    return r
