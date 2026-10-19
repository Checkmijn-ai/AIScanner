"""Kern van de scanner: projectcontext, bevindingen en uitkomsten per check.

Alles werkt met vaste regels: dezelfde code geeft altijd dezelfde uitkomst.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path

ERNST_ORDE = {"Kritiek": 4, "Hoog": 3, "Middel": 2, "Laag": 1, "Info": 0}

# Mappen die we nooit als broncode lezen (wel apart, zie bundle en hygiene).
SKIP_DIRS = {
    ".git", ".aiscan", "node_modules", ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", ".next", ".nuxt", "dist", "build", "out", "coverage", ".gradle",
    "Pods", "vendor", "bower_components", ".idea", ".vscode", "target", ".cache",
}
BUILD_DIRS = {"dist", "build", "out", ".next", "public", "static", "www", "frontend/dist"}

TEXT_EXT = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".py", ".rb", ".php",
    ".java", ".kt", ".go", ".cs", ".swift", ".m", ".json", ".yml", ".yaml", ".toml", ".ini",
    ".cfg", ".conf", ".env", ".md", ".txt", ".html", ".htm", ".xml", ".gradle", ".properties",
    ".sh", ".bash", ".ps1", ".tf", ".sql", ".dockerfile", ".plist", ".mdc",
}
MAX_FILE = 2_000_000  # bytes


@dataclass
class Finding:
    check: str
    ernst: str
    titel: str
    bestand: str = ""
    regel: int = 0
    bewijs: str = ""
    bevestigen: bool = False  # True = de scan markeert, een analist bevestigt

    def key(self):
        return (self.check, self.bestand, self.regel, self.titel)


@dataclass
class Result:
    check: str
    status: str = "Gehaald"  # Gehaald | Bevinding | Niet van toepassing | Niet gescand
    reden: str = ""
    findings: list = field(default_factory=list)
    info: list = field(default_factory=list)  # wat de scan bekeek, voor het rapport

    def add(self, f: Finding):
        self.findings.append(f)


class Project:
    """Alles wat de checks over het project moeten weten, één keer ingelezen."""

    def __init__(self, root: str, offline: bool = True, github_token: str | None = None,
                 url: str | None = None, tools: dict | None = None):
        self.root = Path(root).resolve()
        self.offline = offline
        self.github_token = github_token
        self.url = url
        self.tools = tools or {}
        self.files: list[Path] = []          # broncode en configuratie
        self.build_files: list[Path] = []    # gebouwde uitvoer (dist, build, public)
        self.all_files: list[Path] = []      # alles behalve .git en node_modules
        self._text_cache: dict[Path, str] = {}
        self._walk()
        self.git = (self.root / ".git").exists()
        self.tracked = self._git_tracked()

    # ---------- bestanden
    def _walk(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            rel = Path(dirpath).relative_to(self.root)
            parts = set(rel.parts)
            if ".git" in parts or "node_modules" in parts or ".aiscan" in parts:
                dirnames[:] = []
                continue
            in_build = bool(parts & {"dist", "build", "out", ".next", "public", "static", "www"})
            skip_src = bool(parts & SKIP_DIRS)
            for fn in filenames:
                p = Path(dirpath) / fn
                try:
                    if p.is_symlink() or p.stat().st_size > MAX_FILE:
                        continue
                except OSError:
                    continue
                self.all_files.append(p)
                if in_build:
                    self.build_files.append(p)
                if not skip_src:
                    self.files.append(p)
            dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", ".aiscan"}]

    def _git_tracked(self):
        if not self.git:
            return None
        try:
            out = subprocess.run(["git", "-C", str(self.root), "ls-files"], capture_output=True,
                                 text=True, timeout=60).stdout
            return set(out.splitlines())
        except Exception:
            return None

    def rel(self, p: Path) -> str:
        try:
            return str(p.relative_to(self.root))
        except ValueError:
            return str(p)

    def text(self, p: Path) -> str:
        if p not in self._text_cache:
            try:
                b = p.read_bytes()
                if b"\x00" in b[:4096]:
                    self._text_cache[p] = ""
                else:
                    self._text_cache[p] = b.decode("utf-8", errors="replace")
            except OSError:
                self._text_cache[p] = ""
        return self._text_cache[p]

    def find(self, *patterns, where="files"):
        pool = getattr(self, where)
        out = []
        for p in pool:
            r = self.rel(p)
            name = p.name
            for pat in patterns:
                if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(r, pat):
                    out.append(p)
                    break
        return out

    def source_files(self, exts):
        return [p for p in self.files if p.suffix.lower() in exts]

    # ---------- talen en manifesten
    @property
    def languages(self):
        exts = {p.suffix.lower() for p in self.files}
        langs = set()
        if exts & {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}:
            langs.add("javascript")
        if ".py" in exts:
            langs.add("python")
        if exts & {".java", ".kt", ".gradle"}:
            langs.add("jvm")
        if exts & {".swift", ".m"}:
            langs.add("ios")
        if ".php" in exts:
            langs.add("php")
        return langs

    def json(self, p: Path):
        try:
            return json.loads(self.text(p))
        except Exception:
            return None

    def is_mobile(self):
        return bool(self.find("AndroidManifest.xml", "Podfile", "*.xcodeproj", "Info.plist",
                              "pubspec.yaml", "app.json")) and bool(
            self.find("AndroidManifest.xml", "Podfile", "Info.plist", "pubspec.yaml")
            or any("react-native" in self.text(p) for p in self.find("package.json")))

    def git_head(self):
        if not self.git:
            return None
        try:
            return subprocess.run(["git", "-C", str(self.root), "rev-parse", "HEAD"],
                                  capture_output=True, text=True, timeout=20).stdout.strip() or None
        except Exception:
            return None


VENDOR_NAME = re.compile(r"^(three|jquery|lodash|moment|bootstrap|d3|chart|angular|react|react-dom|vue|underscore|backbone|ember|"
                         r"highlight|prism|codemirror|ace|pdf|socket\.io|leaflet|popper|swiper|gsap|plotly|echarts|tinymce|ckeditor)"
                         r"([.-][\w.-]+)?\.js$", re.I)


def is_vendored(path: Path, text: str) -> bool:
    """Geminificeerde of meegeleverde bibliotheek: niet als eigen code beoordelen."""
    if path.name.endswith((".min.js", ".bundle.js", ".min.css")) or VENDOR_NAME.match(path.name):
        return True
    lines = text.splitlines()[:40]
    if not lines:
        return False
    if any(len(l) > 800 for l in lines[:5]) or sum(len(l) for l in lines) / len(lines) > 250:
        return True
    if len(text) > 150_000 and re.search(r"@license|\(c\) \d{4}|Copyright", text[:3000]):
        return True
    return False


def lines_matching(text: str, regex: re.Pattern):
    for i, line in enumerate(text.splitlines(), 1):
        if regex.search(line):
            yield i, line


def snippet(line: str, n=160):
    s = line.strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def mask(secret: str) -> str:
    s = secret.strip()
    if len(s) <= 8:
        return "****"
    return s[:4] + "…" + "*" * 6 + f" ({len(s)} tekens)"


def to_dict(obj):
    return asdict(obj)


_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{16,}")


def redact(line: str, secret: str = "") -> str:
    """Maskeert het gevonden geheim én elke andere lange, willekeurig ogende tekenreeks op de regel."""
    import math
    from collections import Counter

    def ent(t):
        c = Counter(t)
        return -sum(n / len(t) * math.log2(n / len(t)) for n in c.values())
    if secret:
        line = line.replace(secret, mask(secret))

    def sub(m):
        t = m.group(0)
        if "…" in t or t.isalpha() or t.isdigit() or ent(t) < 3.5 or re.fullmatch(r"[a-z_\-]+|[A-Z_\-]+", t):
            return t
        return mask(t)
    return snippet(_TOKEN.sub(sub, line))
