"""Geheimen opsporen met de regels van gitleaks (MIT-licentie), herschreven voor Python."""
from __future__ import annotations

import json
import math
import re
import subprocess
import warnings
from collections import Counter
from functools import lru_cache
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"
PLACEHOLDER = re.compile(r"(?i)(example|sample|dummy|placeholder|changeme|your[_-]?(api|secret|token|key)|xxxx|<.*>|\$\{|"
                         r"process\.env|os\.environ|getenv|redacted|test[_-]?key|fake|lorem|\*\*\*\*)")


@lru_cache(maxsize=1)
def rules():
    d = json.loads((DATA / "secret_rules.json").read_text())
    compiled = []
    warnings.filterwarnings("ignore", category=FutureWarning)
    for r in d["rules"]:
        try:
            compiled.append({**r, "rx": re.compile(r["regex"]), "path_rx": re.compile(r["path"]) if r.get("path") else None,
                             "allow_rx": [re.compile(x) for grp in r.get("allow", []) for x in grp]})
        except re.error:
            continue
    allow_paths = []
    for p in d.get("allow_paths", []):
        try:
            allow_paths.append(re.compile(p))
        except re.error:
            pass
    allow_rx = []
    for p in d.get("allow_regexes", []):
        try:
            allow_rx.append(re.compile(p))
        except re.error:
            pass
    return compiled, allow_paths, allow_rx


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def scan_text(text: str, path: str = ""):
    """Geeft (regelnummer, rule_id, beschrijving, geheim, regel) terug."""
    rs, allow_paths, allow_rx = rules()
    if any(p.search(path) for p in allow_paths):
        return []
    low = text.lower()
    out = []
    active = [r for r in rs if (not r["keywords"] or any(k in low for k in r["keywords"]))
              and (r.get("path_rx") is None or r["path_rx"].search(path))]
    if not active:
        return out
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if len(line) > 5000:
            line = line[:5000]
        ll = line.lower()
        for r in active:
            if r["keywords"] and not any(k in ll for k in r["keywords"]):
                continue
            for m in r["rx"].finditer(line):
                g = r.get("group") or (1 if m.groups() else 0)
                try:
                    secret = m.group(g) or m.group(0)
                except IndexError:
                    secret = m.group(0)
                if r.get("entropy") and entropy(secret) < float(r["entropy"]):
                    continue
                if PLACEHOLDER.search(secret) or any(a.search(secret) for a in r["allow_rx"]) or any(a.search(secret) for a in allow_rx):
                    continue
                out.append((i, r["id"], r["desc"], secret, line))
                break
    return out


def scan_history(root: Path, max_bytes=50_000_000):
    """Zoekt geheimen in toegevoegde regels van de hele git-geschiedenis."""
    try:
        proc = subprocess.run(["git", "-C", str(root), "log", "-p", "--all", "--no-color", "-U0",
                               "--format=COMMIT %H %ad", "--date=short"],
                              capture_output=True, timeout=300)
    except Exception:
        return None
    data = proc.stdout[:max_bytes].decode("utf-8", errors="replace")
    out, commit, date, fname = [], "", "", ""
    buf = []

    def flush():
        if buf and fname:
            for (ln, rid, desc, secret, line) in scan_text("\n".join(buf), fname):
                out.append((commit, date, fname, rid, desc, secret, line))

    for line in data.splitlines():
        if line.startswith("COMMIT "):
            flush(); buf = []
            parts = line.split()
            commit, date = parts[1][:10], parts[2] if len(parts) > 2 else ""
        elif line.startswith("+++ "):
            flush(); buf = []
            fname = line[6:] if line.startswith("+++ b/") else ""
        elif line.startswith("+") and not line.startswith("+++"):
            buf.append(line[1:])
    flush()
    return out


WORDS = {"api": "API", "key": "sleutel", "token": "token", "access": "toegangs", "secret": "geheim", "private": "privé",
         "pat": "persoonlijk token", "client": "client", "password": "wachtwoord", "webhook": "webhook", "oauth": "OAuth",
         "refresh": "vernieuw", "service": "service", "account": "account", "app": "app", "id": "ID"}
BRANDS = {"openai": "OpenAI", "anthropic": "Anthropic", "github": "GitHub", "gitlab": "GitLab", "aws": "AWS", "gcp": "Google Cloud",
          "stripe": "Stripe", "slack": "Slack", "twilio": "Twilio", "sendgrid": "SendGrid", "azure": "Azure", "google": "Google",
          "jwt": "JWT", "npm": "npm", "pypi": "PyPI", "huggingface": "Hugging Face", "mailgun": "Mailgun", "discord": "Discord",
          "telegram": "Telegram", "shopify": "Shopify", "heroku": "Heroku", "digitalocean": "DigitalOcean", "postman": "Postman",
          "linear": "Linear", "notion": "Notion", "atlassian": "Atlassian", "facebook": "Facebook", "square": "Square",
          "doppler": "Doppler", "dropbox": "Dropbox", "vault": "Vault", "databricks": "Databricks", "sentry": "Sentry"}


def nice(rule_id: str) -> str:
    """Nederlandse naam voor een regel, bv. 'stripe-access-token' -> 'Stripe-toegangstoken'."""
    if rule_id == "generic-api-key":
        return "mogelijk geheim (algemeen patroon)"
    if rule_id == "private-key":
        return "privésleutel"
    parts = rule_id.split("-")
    brand = BRANDS.get(parts[0])
    rest = parts[1:] if brand else parts
    words = []
    for w in rest:
        t = WORDS.get(w, w)
        if words and words[-1].endswith("toegangs"):
            words[-1] = words[-1] + t
        else:
            words.append(t)
    name = " ".join(words).replace("toegangs token", "toegangstoken").replace("API sleutel", "API-sleutel").strip()
    return f"{name} van {brand}" if brand and name else (f"geheim van {brand}" if brand else name or rule_id)
