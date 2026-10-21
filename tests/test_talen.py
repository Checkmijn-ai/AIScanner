"""Pakketten in PHP (Composer), Go, Ruby en Java: inlezen, vergelijken met de lekkenindex; runtimeversies (PHP voorop)."""
import datetime as dt
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from aiscan.core import Project  # noqa: E402
from aiscan.checks import supply  # noqa: E402
from aiscan.deps import all_components  # noqa: E402
from aiscan.versions import affected, key  # noqa: E402

# 1. versies vergelijken
assert key("Go", "v1.2.10") > key("Go", "1.2.9")
assert key("Maven", "5.3.20.RELEASE") == key("Maven", "5.3.20")
assert key("Maven", "2.0.0-beta1") < key("Maven", "2.0.0")
assert key("RubyGems", "1.13.10") > key("RubyGems", "1.13.9.pre")
assert key("Packagist", "v6.4.1") < key("Packagist", "6.4.12")
assert affected("Packagist", "6.4.1", {"r": [[{"introduced": "0"}, {"fixed": "6.4.12"}]]})
assert not affected("Packagist", "6.4.12", {"r": [[{"introduced": "0"}, {"fixed": "6.4.12"}]]})

tmp = Path(tempfile.mkdtemp())
(tmp / "composer.json").write_text('{"require": {"php": "^8.1", "laravel/framework": "^10.0", "ext-json": "*"},'
                                    ' "config": {"platform": {"php": "8.1.2"}}}')
(tmp / "composer.lock").write_text('{"packages": [{"name": "laravel/framework", "version": "v10.0.0", "license": ["MIT"]},'
                                    ' {"name": "guzzlehttp/psr7", "version": "2.4.0"}], "packages-dev": []}')
(tmp / "go.mod").write_text("module x\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n"
                             "\tgolang.org/x/net v0.10.0 // indirect\n)\n")
(tmp / "go.sum").write_text("x\n")
(tmp / "Gemfile.lock").write_text("GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.13.9-x86_64-linux)\n"
                                   "      racc (~> 1.4)\n    rails (7.0.0)\n\nDEPENDENCIES\n  rails\n")
(tmp / "pom.xml").write_text('<project xmlns="http://maven.apache.org/POM/4.0.0"><properties><spring.version>5.3.17</spring.version>'
                              '</properties><dependencies><dependency><groupId>org.springframework</groupId>'
                              '<artifactId>spring-core</artifactId><version>${spring.version}</version></dependency>'
                              '</dependencies></project>')
(tmp / "Dockerfile").write_text("FROM php:8.3.12-fpm\n")

proj = Project(str(tmp))
comps = {(c.ecosystem, c.name): c for c in all_components(proj)}
assert comps[("Packagist", "laravel/framework")].version == "10.0.0" and comps[("Packagist", "laravel/framework")].direct
assert not comps[("Packagist", "guzzlehttp/psr7")].direct and ("Packagist", "php") not in comps and ("Packagist", "ext-json") not in comps
assert comps[("Go", "github.com/gin-gonic/gin")].direct and not comps[("Go", "golang.org/x/net")].direct
assert comps[("RubyGems", "nokogiri")].version == "1.13.9" and comps[("RubyGems", "rails")].direct
assert comps[("Maven", "org.springframework:spring-core")].version == "5.3.17"
assert comps[("Packagist", "laravel/framework")].purl == "pkg:composer/laravel/framework@10.0.0"

# 2. lekken vinden met een kleine nep-index
rec = lambda i, fix: {"id": i, "cve": [], "sev": "HIGH", "sum": "lek", "r": [[{"introduced": "0"}, {"fixed": fix}]], "v": [], "mal": False}  # noqa: E731
supply.advisories.cache_clear()
supply.advisories = lambda: {"meta": {"bron": "test", "stand": "x"}, "idx": {
    "npm": {}, "PyPI": {},
    "Packagist": {"laravel/framework": [rec("GHSA-php1", "10.1.0")]},
    "Go": {"github.com/gin-gonic/gin": [rec("GHSA-go1", "1.9.1")]},
    "RubyGems": {"nokogiri": [rec("GHSA-rb1", "1.13.10")]},
    "Maven": {"org.springframework:spring-core": [rec("GHSA-jv1", "5.3.18")]}}}
r = supply.known_vulns(proj, {"ernst": "Hoog"})
titels = " | ".join(f.titel + " " + f.bewijs for f in r.findings)
for verwacht in ("laravel/framework 10.0.0", "bijwerken naar minstens 10.1.0", "github.com/gin-gonic/gin 1.9.0", "nokogiri 1.13.9",
                 "org.springframework:spring-core 5.3.17", "5.3.18"):
    assert verwacht in titels, (verwacht, titels)

# 3. runtimes: PHP 8.1 buiten ondersteuning (vaste tabel), en php:8.3.12 loopt achter op de nieuwste
supply.runtimes.cache_clear()
vandaag = dt.date.today().isoformat()
supply.runtimes = lambda: {"php": {"8.1": {"eol": "2025-12-31", "laatste": "8.1.33", "datum": "2025-07-03"},
                                    "8.3": {"eol": "2027-12-31", "laatste": "8.3.27", "datum": vandaag}}}
r = supply.eol(proj, {"ernst": "Hoog"})
f = {x.titel: x for x in r.findings}
assert any(t.startswith("PHP 8.1.2 krijgt geen beveiligingsupdates meer") for t in f), f
nieuw = next(x for t, x in f.items() if t.startswith("PHP 8.3.12: er is een nieuwere versie, 8.3.27"))
assert nieuw.ernst == "Middel" and "net uit" in nieuw.bewijs and nieuw.bestand == "Dockerfile"

# 4. C-19 slaat de nieuwe talen over (geen valse 'ongebruikt' voor Composer)
r = supply.unused(proj, {"ernst": "Laag"})
assert not any("laravel" in x.titel for x in r.findings)
print("ok: talen (Composer, Go, Ruby, Java) en runtimes")
