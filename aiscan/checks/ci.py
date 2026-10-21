"""Pipeline: tests automatisch (D-02), beveiligingsscans in de pipeline (D-06), doorlopende bewaking (G-08)."""
from __future__ import annotations

import re

from . import check
from ..core import Finding, Result, snippet

CI_FILES = (".github/workflows/*.yml", ".github/workflows/*.yaml", ".gitlab-ci.yml", "azure-pipelines.yml",
            "bitbucket-pipelines.yml", "Jenkinsfile", ".circleci/config.yml", ".drone.yml", "buildkite.yml")
TEST = re.compile(r"\b((npm|yarn|pnpm|bun) (run )?test\b|bun test|deno test|turbo (run )?test|nx (run-many -t )?test|"
                  r"npx (jest|vitest|mocha|playwright test|cypress run)|"
                  r"\bjest\b|\bvitest\b|\bmocha\b|pytest|python -m (pytest|unittest)|\btox\b|go test|mvn (-B )?(verify|test)|"
                  r"gradlew? test|rspec|phpunit|dotnet test|cargo test|nox\b)")
SAST = re.compile(r"(codeql|semgrep|opengrep|sonar(cloud|qube|-scanner)?|snyk code|\bbandit\b|njsscan|gosec|"
                  r"eslint-plugin-security|horusec|checkmarx|veracode|fortify)", re.I)
DEPSCAN = re.compile(r"(npm audit|yarn (npm )?audit|pnpm audit|pip-audit|osv-scanner|google/osv-scanner|\btrivy\b|"
                     r"snyk (test|monitor)|snyk/actions|\bsafety (check|scan)\b|dependency-check|\bgrype\b|"
                     r"dependency-review-action|retire\b|audit-ci)", re.I)
THRESHOLD = re.compile(r"(--audit-level|--severity-threshold|severity-cutoff|fail-on|exit-code:\s*['\"]?1|--fail-on|"
                       r"--exit-code 1|fail-on-severity|--error)", re.I)
SOFT = re.compile(r"(continue-on-error:\s*true|\|\|\s*(true|exit 0)|allow_failure:\s*true)", re.I)


def ci_files(proj):
    return proj.find(*CI_FILES, where="all_files")


@check("D-02")
def tests_in_ci(proj, meta):
    r = Result("D-02")
    files = ci_files(proj)
    if not files:
        r.add(Finding("D-02", meta["ernst"], "Geen pipeline gevonden: tests draaien niet automatisch bij elke wijziging",
                      bewijs="Geen GitHub Actions, GitLab CI, Azure Pipelines, Bitbucket, Jenkins of CircleCI-configuratie."))
        return r
    ran = False
    for p in files:
        lines = proj.text(p).splitlines()
        for i, line in enumerate(lines, 1):
            if TEST.search(line) and not line.strip().startswith("#"):
                ran = True
                ctx = "\n".join(lines[max(0, i - 4): i + 3])
                if SOFT.search(ctx):
                    r.add(Finding("D-02", "Middel", "Teststap mag falen zonder de build te stoppen", proj.rel(p), i, snippet(line)))
        text = proj.text(p)
        if ".github/workflows" in proj.rel(p) and not re.search(r"\b(push|pull_request|merge_group)\b", text):
            r.info.append(f"{proj.rel(p)} draait niet bij push of pull request.")
    if not ran:
        r.add(Finding("D-02", meta["ernst"], "De pipeline voert geen tests uit",
                      ", ".join(proj.rel(p) for p in files)[:200]))
    r.info.append("Of een falende test de release echt blokkeert, hangt ook af van de branchbeveiliging (R-03).")
    return r


@check("D-06")
def security_in_ci(proj, meta):
    r = Result("D-06")
    files = ci_files(proj)
    text = "\n".join(proj.text(p) for p in files)
    dependabot = proj.find(".github/dependabot.yml", ".github/dependabot.yaml", where="all_files")
    if not files:
        r.add(Finding("D-06", meta["ernst"], "Geen pipeline gevonden: geen beveiligingsanalyse bij elke wijziging"))
        return r
    if not SAST.search(text):
        r.add(Finding("D-06", meta["ernst"], "Geen statische beveiligingsanalyse (SAST) in de pipeline",
                      ", ".join(proj.rel(p) for p in files)[:200]))
    if not DEPSCAN.search(text):
        r.add(Finding("D-06", meta["ernst"], "Geen scan van afhankelijkheden in de pipeline",
                      bewijs="Dependabot-meldingen alleen blokkeren een release niet." if dependabot else ""))
    if (SAST.search(text) or DEPSCAN.search(text)) and not THRESHOLD.search(text) and "codeql" not in text.lower():
        r.add(Finding("D-06", "Laag", "Beveiligingsscan zonder drempel die de release blokkeert", bevestigen=True))
    if SOFT.search(text) and (SAST.search(text) or DEPSCAN.search(text)):
        r.info.append("Let op: in de pipeline staan stappen die mogen falen (continue-on-error of || true).")
    return r


@check("G-08")
def monitoring(proj, meta):
    r = Result("G-08")
    bots = proj.find(".github/dependabot.yml", ".github/dependabot.yaml", "renovate.json", ".renovaterc*",
                     ".github/renovate.json*", ".snyk", where="all_files")
    sched = [p for p in ci_files(proj) if re.search(r"schedule:|cron", proj.text(p)) and DEPSCAN.search(proj.text(p))]
    if bots:
        r.info.append("Bewaking via " + ", ".join(proj.rel(p) for p in bots))
    if sched:
        r.info.append("Geplande scan van afhankelijkheden in " + ", ".join(proj.rel(p) for p in sched))
    if not bots and not sched:
        r.add(Finding("G-08", meta["ernst"], "Geen doorlopende bewaking van nieuwe kwetsbaarheden in afhankelijkheden",
                      bewijs="Geen Dependabot, Renovate, Snyk of geplande scan gevonden. Met de SBOM uit dit rapport kan de "
                             "maandelijkse bewaking van de scanner dit opvangen."))
    return r
