"""Afhankelijkheden inlezen uit manifesten en lockfiles: npm, yarn, pnpm, bun, pip, Pipenv, Poetry, uv, Composer (PHP),
Go-modules, Bundler (Ruby) en Maven/Gradle (Java)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    tomllib = None
import yaml


@dataclass
class Component:
    name: str
    version: str | None
    ecosystem: str            # npm | PyPI | Packagist | Go | RubyGems | Maven (namen zoals in de GitHub Advisory Database)
    direct: bool = False
    dev: bool = False
    integrity: str | None = None
    resolved: str | None = None
    license: str | None = None
    source: str = ""          # bestand waaruit gelezen
    paths: list = field(default_factory=list)
    spec: str | None = None     # versiebereik als er geen vaste versie is

    @property
    def purl(self):
        v = f"@{self.version}" if self.version else ""
        if self.ecosystem == "npm":
            n = self.name.replace("@", "%40", 1) if self.name.startswith("@") else self.name
            return f"pkg:npm/{n}{v}"
        if self.ecosystem == "Packagist":
            return f"pkg:composer/{self.name}{v}"
        if self.ecosystem == "Go":
            return f"pkg:golang/{self.name}{v}"
        if self.ecosystem == "RubyGems":
            return f"pkg:gem/{self.name}{v}"
        if self.ecosystem == "Maven":
            g, _, a = self.name.partition(":")
            return f"pkg:maven/{g}/{a}{v}"
        return f"pkg:pypi/{self.name.lower()}{v}"


@dataclass
class Manifest:
    path: Path
    ecosystem: str
    direct: dict            # naam -> versiebereik
    dev: dict
    lockfile: Path | None = None
    components: list = field(default_factory=list)
    lock_has_integrity: bool = False
    other_lockfiles: list = field(default_factory=list)   # [(pad, ontbrekende directe pakketten)]


def norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------- npm
def _npm_lock(proj, lock: Path, direct, dev):
    d = proj.json(lock) or {}
    comps = {}
    integ = True
    pk = d.get("packages")
    if isinstance(pk, dict):  # lockfile v2/v3
        for path, info in pk.items():
            if not path:
                continue
            name = info.get("name") or path.split("node_modules/")[-1]
            ver = info.get("version")
            if info.get("link"):
                continue
            if not info.get("integrity") and not info.get("bundled") and info.get("resolved", "").startswith("http"):
                integ = False
            key = (name, ver)
            c = comps.get(key)
            if not c:
                c = comps[key] = Component(name, ver, "npm", direct=name in direct or name in dev,
                                           dev=bool(info.get("dev")), integrity=info.get("integrity"),
                                           resolved=info.get("resolved"), license=info.get("license"),
                                           source=proj.rel(lock))
            c.paths.append(path)
    else:  # lockfile v1
        def walk(deps, prefix):
            nonlocal integ
            for name, info in (deps or {}).items():
                ver = info.get("version")
                if not info.get("integrity") and str(info.get("resolved", "")).startswith("http"):
                    integ = False
                key = (name, ver)
                if key not in comps:
                    comps[key] = Component(name, ver, "npm", direct=name in direct or name in dev,
                                           dev=bool(info.get("dev")), integrity=info.get("integrity"),
                                           resolved=info.get("resolved"), source=proj.rel(lock))
                comps[key].paths.append(prefix + name)
                walk(info.get("dependencies"), prefix + name + ">")
        walk(d.get("dependencies"), "")
    return list(comps.values()), integ


def _bun_lock(proj, lock: Path, direct, dev):
    """bun.lock (tekst, JSON met komma's achteraan). bun.lockb (binair) wordt niet gelezen."""
    import json as _json
    text = re.sub(r",(\s*[}\]])", r"\1", proj.text(lock))
    try:
        d = _json.loads(text)
    except Exception:
        return [], False
    comps, integ = {}, True
    # welke pakketten zijn alleen nodig voor ontwikkeling? (niet bereikbaar vanuit de gewone dependencies)
    # Een peer-afhankelijkheid levert het project zelf. Staat ze bij de devDependencies van het project (bv.
    # tailwindcss onder tailwindcss-animate), dan is ze alleen voor ontwikkeling en volgen we ze niet.
    graaf = {}
    for key, entry in (d.get("packages") or {}).items():
        if isinstance(entry, list) and len(entry) > 2 and isinstance(entry[2], dict):
            naam = entry[0][:entry[0].rfind("@")] if isinstance(entry[0], str) and entry[0].rfind("@") > 0 else key
            for sect in ("dependencies", "optionalDependencies"):
                graaf.setdefault(naam, set()).update((entry[2].get(sect) or {}).keys())
            graaf.setdefault(naam, set()).update(n for n in (entry[2].get("peerDependencies") or {}) if n not in dev)
    prod, stapel = set(), [n for n in direct if n not in dev]
    while stapel:
        n = stapel.pop()
        if n not in prod:
            prod.add(n)
            stapel.extend(graaf.get(n, ()))
    for key, entry in (d.get("packages") or {}).items():
        if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
            continue
        spec = entry[0]
        at = spec.rfind("@")
        if at <= 0:
            continue
        name, ver = spec[:at], spec[at + 1:]
        if ver.startswith(("workspace:", "link:", "file:")):
            continue
        sha = next((x for x in entry[1:] if isinstance(x, str) and x.startswith("sha")), None)
        if not sha:
            integ = False
        k = (name, ver)
        if k not in comps:
            comps[k] = Component(name, ver, "npm", direct=name in direct or name in dev, dev=name not in prod,
                                 integrity=sha, source=proj.rel(lock))
        comps[k].paths.append(key)
    return list(comps.values()), integ


def _yarn_lock(proj, lock: Path, direct, dev):
    comps, integ = {}, True
    text = proj.text(lock)
    blocks = re.split(r"\n(?=\S)", text)
    for b in blocks:
        head = b.split("\n", 1)[0].strip().rstrip(":")
        if not head or head.startswith("#") or head.startswith("__metadata"):
            continue
        first = head.split(",")[0].strip().strip('"')
        name = first.rsplit("@", 1)[0] if not first.startswith("@") else "@" + first[1:].rsplit("@", 1)[0]
        m = re.search(r'^\s+version:?\s+"?([^"\s]+)"?', b, re.M)
        ver = m.group(1) if m else None
        has_int = bool(re.search(r"^\s+(integrity|checksum)", b, re.M))
        integ = integ and has_int
        comps[(name, ver)] = Component(name, ver, "npm", direct=name in direct or name in dev,
                                       integrity="yes" if has_int else None, source=proj.rel(lock))
    return list(comps.values()), integ


def _pnpm_lock(proj, lock: Path, direct, dev):
    comps, integ = {}, True
    try:
        d = yaml.safe_load(proj.text(lock)) or {}
    except Exception:
        return [], False
    for key, info in (d.get("packages") or {}).items():
        k = key.lstrip("/")
        m = re.match(r"(@?[^@]+)@([^()]+)", k) or re.match(r"(@?[^/]+(?:/[^/]+)?)/([^/]+)$", k)
        if not m:
            continue
        name, ver = m.group(1), m.group(2)
        res = (info or {}).get("resolution", {}) if isinstance(info, dict) else {}
        if not res.get("integrity"):
            integ = False
        comps[(name, ver)] = Component(name, ver, "npm", direct=name in direct or name in dev,
                                       integrity=res.get("integrity"), source=proj.rel(lock))
    return list(comps.values()), integ


def npm_manifests(proj) -> list[Manifest]:
    out = []
    for pj in proj.find("package.json"):
        d = proj.json(pj)
        if not isinstance(d, dict):
            continue
        direct = d.get("dependencies") or {}
        dev = d.get("devDependencies") or {}
        m = Manifest(pj, "npm", direct, dev)
        # Alle lockfiles lezen en de lockfile kiezen die het best bij package.json past (Lovable en bun hebben er
        # soms twee: een verouderde package-lock.json naast bun.lock).
        found = []
        for lname, parser in (("package-lock.json", _npm_lock), ("npm-shrinkwrap.json", _npm_lock),
                              ("bun.lock", _bun_lock), ("yarn.lock", _yarn_lock), ("pnpm-lock.yaml", _pnpm_lock)):
            lp = pj.parent / lname
            if lp.exists():
                comps, integ = parser(proj, lp, direct, dev)
                names = {c.name for c in comps}
                missing = [n for n in list(direct) + list(dev) if n not in names]
                found.append((len(missing), lp, comps, integ, missing))
        if found:
            found.sort(key=lambda x: x[0])
            _, m.lockfile, m.components, m.lock_has_integrity, _ = found[0]
            m.other_lockfiles = [(lp, missing) for _, lp, _, _, missing in found[1:]]
        if not m.lockfile:
            # geen lockfile: alleen directe afhankelijkheden, versie = bereik
            for n, v in {**direct, **dev}.items():
                m.components.append(Component(n, None, "npm", direct=True, dev=n in dev,
                                              source=proj.rel(pj), paths=[n], spec=str(v)))
        out.append(m)
    return out


# ---------------- Python
REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(===|==|~=|>=|<=|>|<|!=)?\s*([^;#\s]*)")


def _req_file(proj, p: Path):
    direct, comps, pinned_all, hashed = {}, [], True, True
    for line in proj.text(p).splitlines():
        s = line.strip()
        if not s or s.startswith(("#", "-r", "-c", "--", "-e", "git+", "http")):
            if s.startswith("--hash"):
                continue
            continue
        m = REQ_LINE.match(s)
        if not m:
            continue
        name, op, ver = m.group(1), m.group(3), m.group(4)
        direct[name] = (op or "") + (ver or "")
        pinned = op in ("==", "===") and ver and "*" not in ver
        pinned_all = pinned_all and bool(pinned)
        if "--hash" not in line:
            hashed = False
        comps.append(Component(norm_py(name), ver if pinned else None, "PyPI", direct=True,
                               source=proj.rel(p), paths=[name], spec=(op or "") + (ver or "")))
    return direct, comps, pinned_all, hashed


def py_manifests(proj) -> list[Manifest]:
    out = []
    for p in proj.find("requirements*.txt", "requirements/*.txt"):
        direct, comps, pinned, hashed = _req_file(proj, p)
        m = Manifest(p, "PyPI", direct, {})
        if pinned and comps:
            m.lockfile = p
            m.lock_has_integrity = hashed
        m.components = comps
        out.append(m)
    for p in proj.find("Pipfile.lock"):
        d = proj.json(p) or {}
        m = Manifest(p, "PyPI", {}, {}, lockfile=p)
        integ = True
        for sect, isdev in (("default", False), ("develop", True)):
            for n, info in (d.get(sect) or {}).items():
                ver = str(info.get("version", "")).lstrip("=") or None
                if not info.get("hashes"):
                    integ = False
                (m.dev if isdev else m.direct)[n] = ver
                m.components.append(Component(norm_py(n), ver, "PyPI", direct=True, dev=isdev,
                                              integrity="hashes" if info.get("hashes") else None,
                                              source=proj.rel(p), paths=[n]))
        m.lock_has_integrity = integ
        out.append(m)
    for p in proj.find("pyproject.toml"):
        if tomllib is None:
            break
        try:
            d = tomllib.loads(proj.text(p))
        except Exception:
            continue
        direct = {}
        for dep in (d.get("project", {}).get("dependencies") or []):
            mm = REQ_LINE.match(dep)
            if mm:
                direct[mm.group(1)] = (mm.group(3) or "") + (mm.group(4) or "")
        poetry = d.get("tool", {}).get("poetry", {})
        for n, v in (poetry.get("dependencies") or {}).items():
            if n.lower() != "python":
                direct[n] = v if isinstance(v, str) else str(v.get("version", ""))
        if not direct:
            continue
        m = Manifest(p, "PyPI", direct, {})
        for lname in ("poetry.lock", "uv.lock", "pdm.lock"):
            lp = p.parent / lname
            if lp.exists():
                m.lockfile = lp
                try:
                    ld = tomllib.loads(proj.text(lp))
                except Exception:
                    ld = {}
                integ = True
                for pkg in ld.get("package", []):
                    n = pkg.get("name")
                    has = bool(pkg.get("files") or pkg.get("sdist") or pkg.get("wheels"))
                    integ = integ and has
                    m.components.append(Component(norm_py(n), pkg.get("version"), "PyPI",
                                                  direct=norm_py(n) in {norm_py(x) for x in direct},
                                                  integrity="hashes" if has else None, source=proj.rel(lp), paths=[n]))
                m.lock_has_integrity = integ
                break
        if not m.lockfile:
            m.components = [Component(norm_py(n), None, "PyPI", direct=True, source=proj.rel(p), paths=[n])
                            for n in direct]
        out.append(m)
    return out


# ---------------- PHP (Composer)
def php_manifests(proj) -> list[Manifest]:
    out = []
    for cj in proj.find("composer.json"):
        d = proj.json(cj)
        if not isinstance(d, dict):
            continue
        plat = lambda n: n == "php" or n.startswith(("ext-", "lib-")) or n in ("composer-plugin-api", "composer-runtime-api")  # noqa: E731
        direct = {n.lower(): v for n, v in (d.get("require") or {}).items() if not plat(n)}
        dev = {n.lower(): v for n, v in (d.get("require-dev") or {}).items() if not plat(n)}
        m = Manifest(cj, "Packagist", direct, dev)
        lp = cj.parent / "composer.lock"
        ld = proj.json(lp) if lp.exists() else None
        if isinstance(ld, dict):
            m.lockfile = lp
            m.lock_has_integrity = True  # Composer controleert pakketten via de bron; geen aparte melding
            for sect, isdev in (("packages", False), ("packages-dev", True)):
                for pkg in ld.get(sect) or []:
                    n = str(pkg.get("name", "")).lower()
                    if not n:
                        continue
                    lic = pkg.get("license")
                    m.components.append(Component(n, str(pkg.get("version", "")).lstrip("v") or None, "Packagist",
                                                  direct=n in direct or n in dev, dev=isdev,
                                                  license=", ".join(lic) if isinstance(lic, list) else lic,
                                                  source=proj.rel(lp), paths=[n]))
        else:
            for n, v in {**direct, **dev}.items():
                m.components.append(Component(n, None, "Packagist", direct=True, dev=n in dev,
                                              source=proj.rel(cj), paths=[n], spec=str(v)))
        out.append(m)
    return out


# ---------------- Go
def go_manifests(proj) -> list[Manifest]:
    out = []
    for gm in proj.find("go.mod"):
        tekst = proj.text(gm)
        direct, comps = {}, []
        blok = False
        for regel in tekst.splitlines():
            r = regel.split("//")[0].strip()
            ind = "// indirect" in regel
            if r.startswith("require ("):
                blok = True
                continue
            if blok and r == ")":
                blok = False
                continue
            mm = None
            if blok:
                mm = re.match(r"(\S+)\s+(v\S+)", r)
            elif r.startswith("require "):
                mm = re.match(r"require\s+(\S+)\s+(v\S+)", r)
            if mm:
                n, v = mm.group(1), mm.group(2)
                if not ind:
                    direct[n] = v
                comps.append(Component(n, v.lstrip("v").replace("+incompatible", ""), "Go", direct=not ind,
                                       source=proj.rel(gm), paths=[n]))
        if not comps:
            continue
        m = Manifest(gm, "Go", direct, {}, lockfile=gm, components=comps)
        m.lock_has_integrity = (gm.parent / "go.sum").exists()
        out.append(m)
    return out


# ---------------- Ruby (Bundler)
def ruby_manifests(proj) -> list[Manifest]:
    out = []
    for gl in proj.find("Gemfile.lock"):
        tekst = proj.text(gl)
        sectie, comps, direct = "", [], {}
        for regel in tekst.splitlines():
            if regel and not regel.startswith(" "):
                sectie = regel.strip()
                continue
            if sectie == "DEPENDENCIES":
                mm = re.match(r"\s{2}([A-Za-z0-9_.\-]+)", regel)
                if mm:
                    direct[mm.group(1)] = ""
            mm = re.match(r"^\s{4}([A-Za-z0-9_.\-]+) \(([^)]+)\)$", regel)
            if mm and sectie in ("GEM", "GIT", "PATH"):
                ver = re.sub(r"-(x86|arm|aarch|java|universal|x64|mingw|darwin|linux).*$", "", mm.group(2))
                comps.append(Component(mm.group(1), ver, "RubyGems", source=proj.rel(gl), paths=[mm.group(1)]))
        for c in comps:
            c.direct = c.name in direct
        if comps:
            out.append(Manifest(gl, "RubyGems", direct, {}, lockfile=gl, components=comps, lock_has_integrity=True))
    for gf in proj.find("Gemfile"):
        if (gf.parent / "Gemfile.lock").exists():
            continue
        direct = {mm.group(1): mm.group(2) or "" for mm in re.finditer(r"^\s*gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", proj.text(gf), re.M)}
        if direct:
            out.append(Manifest(gf, "RubyGems", direct, {}, components=[
                Component(n, None, "RubyGems", direct=True, source=proj.rel(gf), paths=[n], spec=v) for n, v in direct.items()]))
    return out


# ---------------- Java (Maven en Gradle)
def java_manifests(proj) -> list[Manifest]:
    import xml.etree.ElementTree as ET
    out = []
    for pom in proj.find("pom.xml"):
        try:
            tekst = proj.text(pom)
            if "<!ENTITY" in tekst:
                continue
            root = ET.fromstring(tekst)
        except Exception:
            continue
        ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
        q = (lambda t: f"m:{t}") if ns else (lambda t: t)
        props = {}
        pe = root.find(q("properties"), ns)
        if pe is not None:
            for el in pe:
                props[el.tag.split("}")[-1]] = (el.text or "").strip()
        pv = root.find(q("version"), ns)
        if pv is not None:
            props["project.version"] = (pv.text or "").strip()
        direct, comps = {}, []
        for dep in root.iter(("{%s}dependency" % ns["m"]) if ns else "dependency"):
            g = dep.find(q("groupId"), ns)
            a = dep.find(q("artifactId"), ns)
            v = dep.find(q("version"), ns)
            sc = dep.find(q("scope"), ns)
            if g is None or a is None:
                continue
            ver = (v.text or "").strip() if v is not None else ""
            ver = re.sub(r"\$\{([^}]+)\}", lambda x: props.get(x.group(1), x.group(0)), ver)
            n = f"{(g.text or '').strip()}:{(a.text or '').strip()}"
            direct[n] = ver
            vast = ver if ver and "$" not in ver and not ver.startswith(("[", "(")) else None
            comps.append(Component(n, vast, "Maven", direct=True, dev=(sc is not None and (sc.text or "").strip() == "test"),
                                   source=proj.rel(pom), paths=[n], spec=None if vast else ver or None))
        if comps:
            # Maven heeft geen lockfile: de versies in pom.xml liggen vast, de indirecte niet.
            out.append(Manifest(pom, "Maven", direct, {}, lockfile=pom, components=comps, lock_has_integrity=True))
    for gl in proj.find("gradle.lockfile", "*/gradle.lockfile"):
        comps = []
        for regel in proj.text(gl).splitlines():
            mm = re.match(r"^([^#:\s]+):([^:\s]+):([^=\s]+)=(.*)$", regel.strip())
            if mm:
                comps.append(Component(f"{mm.group(1)}:{mm.group(2)}", mm.group(3), "Maven",
                                       dev="test" in mm.group(4).lower() and "runtime" not in mm.group(4).lower(),
                                       source=proj.rel(gl), paths=[mm.group(2)]))
        if comps:
            out.append(Manifest(gl, "Maven", {}, {}, lockfile=gl, components=comps, lock_has_integrity=True))
    for bg in proj.find("build.gradle", "build.gradle.kts"):
        if (bg.parent / "gradle.lockfile").exists():
            continue
        direct, comps = {}, []
        for mm in re.finditer(r"""(implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(?\s*['"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['"]""", proj.text(bg)):
            n = f"{mm.group(2)}:{mm.group(3)}"
            direct[n] = mm.group(4)
            comps.append(Component(n, mm.group(4), "Maven", direct=True, dev=mm.group(1).startswith("test"),
                                   source=proj.rel(bg), paths=[n]))
        if comps:
            out.append(Manifest(bg, "Maven", direct, {}, components=comps))
    return out


def pnaam(c) -> str:
    """De naam zoals in de lekkendatabank: PyPI genormaliseerd, Composer in kleine letters."""
    if c.ecosystem == "PyPI":
        return norm_py(c.name)
    if c.ecosystem == "Packagist":
        return c.name.lower()
    return c.name


def all_manifests(proj):
    if not hasattr(proj, "_manifests"):
        proj._manifests = (npm_manifests(proj) + py_manifests(proj) + php_manifests(proj) + go_manifests(proj)
                           + ruby_manifests(proj) + java_manifests(proj))
    return proj._manifests


def all_components(proj):
    seen, out = set(), []
    for m in all_manifests(proj):
        for c in m.components:
            k = (c.ecosystem, c.name, c.version)
            if k not in seen:
                seen.add(k)
                out.append(c)
    return out


def min_version(spec: str | None):
    """Laagste versie die een bereik toelaat (^1.2.3, ~1.2, >=1.2, 1.2.x), of None."""
    import re as _re
    if not spec or _re.search(r"(git|http|file:|link:|workspace:|\*|latest|<)", spec):
        return None
    m = _re.search(r"(\d+)(?:\.(\d+|x))?(?:\.(\d+|x))?", spec)
    if not m:
        return None
    parts = [m.group(1), m.group(2) or "0", m.group(3) or "0"]
    return ".".join("0" if x == "x" else x for x in parts)
