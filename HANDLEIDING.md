# aiscan 0.2 — handleiding (concept)

aiscan controleert software die met AI gebouwd is, of AI bevat, op de 47 scans van niveau 1. Elke uitkomst is gekoppeld aan de norm of wet waar de scan uit komt. De scanner werkt met vaste regels, zonder AI in de scan zelf: dezelfde code geeft altijd dezelfde uitkomst.

Dit is een werkend concept. Het is bruikbaar voor de eerste betaalde scans, met een analist die de uitkomst naleest. Voor een product dat breed verkocht wordt, moet een ontwikkelaar het afmaken (zie onderaan).

## 1. Installeren

Nodig: Python 3.11 of nieuwer en git.

```
pip install -r requirements.txt
```

Of als commando: `pip install .`, daarna `aiscan` in plaats van `python -m aiscan`.

## 2. Een scan draaien

```
python -m aiscan /pad/naar/project --klant "Klant BV" --app "Naam app" --versie 1.4.0 --uitvoerder "[Bedrijfsnaam]"
```

Na enkele seconden tot een halve minuut staan er drie bestanden in de map `aiscan-rapport`:

| Bestand | Wat |
| --- | --- |
| `rapport.html` | Het rapport voor de klant. Open in een browser; afdrukken naar PDF gaat via de browser. |
| `rapport.json` | Dezelfde uitkomst als gegevens, voor een platform of een eigen overzicht. |
| `sbom.json` | De lijst van alle onderdelen (CycloneDX 1.5). Bewaren voor de maandelijkse bewaking. |

**Opties**

| Optie | Wat |
| --- | --- |
| `--url https://app.klant.be` | Ook de live site controleren: poorten, TLS, headers, cookies, e-mail en DNS (D-12, E-08, O-04, O-05, O-06, Y-01, Y-02, Y-04) |
| `--github-token TOKEN` | Branchbeveiliging en repository-instellingen via de API van GitHub (R-03, R-13); een token met alleen leesrechten volstaat |
| `--offline` | Geen netwerk: geen controle in de pakketregisters, de API van GitHub of de live site |
| `--alleen E-05,F-01` | Alleen deze scans draaien |
| `--out map` | Andere uitvoermap |
| `--scope "tekst"` | Eigen omschrijving van de scope op het voorblad |

Zonder `--offline` kijkt de scanner in npm en PyPI of elk pakket bestaat en hoe oud het is. Zo vindt hij pakketnamen die een AI-assistent verzonnen heeft.

De uitgangscode is 0 als er geen kritieke of hoge bevindingen zijn, anders 2. Zo kan de scanner ook in een pipeline draaien.

**In je AI-agent:** zie [MCP.md](MCP.md). De agent roept de scan zelf aan, zonder netwerk, en herstelt wat hij vindt.

**De scanscore A–G** staat bovenaan het rapport. Per scan telt de zwaarste bevinding. Een zelfscan (niveau 1) haalt hoogstens een C; A en B zijn er alleen na een keuring. De grenzen staan achteraan in het rapport en in MCP.md. Met `--soort "Geverifieerde scan"` vermeldt het rapport dat een erkende uitvoerder de scan deed; standaard is het een zelfscan.

## 3. Voor elke scan

1. **Schriftelijke toestemming** van de eigenaar, met scope, omgeving en periode. Vooral voor `--url`: zonder toestemming een site scannen kan strafbaar zijn.
2. **De code blijft bij de klant.** Draai de scanner op een machine van de klant of in hun pipeline, en neem alleen de rapportmap mee. Geheimen staan gemaskeerd in het rapport.
3. **Scan na de build** als je ook de gebouwde frontend wilt controleren (U-01, U-02), en na `npm ci` of `pip install` als je licenties wilt zien (F-05).
4. **Ruim op.** Verwijder kopieën van de code na de scan; bewaar het rapport en de SBOM.

## 4. Het rapport lezen

| Status | Betekenis |
| --- | --- |
| Geen bevinding | De scan draaide en vond niets. Dat is geen bewijs dat alles in orde is: alleen dat deze controle niets vond |
| Bevinding | De scan vond minstens één punt; zie de details |
| Niet van toepassing | Bijvoorbeeld geen mobiele app, of geen AI in het product |
| Niet gescand | Er ontbrak iets: geen URL, geen token, geen lockfile, geen netwerk. De reden staat erbij |

Ernst: **Kritiek** (direct misbruikbaar), **Hoog**, **Middel**, **Laag**.

**"Te bevestigen"** betekent dat een vast patroon iets markeerde dat niet zeker is. Op niveau 2 bevestigt of verwerpt een analist elke gemarkeerde bevinding. Een analist kan ook de ernst aanpassen, met een motivatie.

Het rapport zegt nooit dat een app "in orde" is met een wet. Het telt per wet en norm hoeveel scans eraan gekoppeld zijn en wat de uitkomst was.

## 5. Bijwerken

- **Lekkendatabank** (maandelijks): haal de GitHub Advisory Database op en bouw de index opnieuw:
  ```
  git clone --depth 1 --filter=blob:none --sparse https://github.com/github/advisory-database
  cd advisory-database && git sparse-checkout set advisories/github-reviewed && cd ..
  python tools/build_advisory_index.py advisory-database aiscan/data/advisories.json.gz 2026-11-17
  ```
- **Einddata, populaire en verouderde pakketten**: `aiscan/data/reference.yaml`.
- **De scans zelf**: `aiscan/data/checks.yaml` (tekst, normen, standaardernst, methode).

Elke wijziging in `aiscan/data` geeft een andere regelset-code. Die staat op het voorblad, zodat je altijd weet met welke regels een rapport gemaakt is.

## 6. Testen

```
python tests/test_demo.py
```

Dit bouwt de demo-app Factuurhulp, een app met bekende fouten en nepsleutels, en de herstelde versie ervan. Daarna controleert de test:
- dat de scanner elke verwachte fout vindt;
- dat er geen geheim in het rapport of in het antwoord aan de agent staat;
- dat de foute app een G krijgt en de herstelde een C;
- dat de MCP-server werkt met het netwerk geblokkeerd.

Draai de test na elke wijziging aan de regels.

## 7. Opbouw van de code

```
aiscan/
  __main__.py        opdrachtregel
  mcp_server.py      MCP-server voor AI-agents (stdio, netwerk geblokkeerd)
  score.py           scanscore A–G
  runner.py          draait de checks, maakt de samenvatting per wet en norm
  core.py            project inlezen, bevindingen, uitkomsten
  deps.py            npm, yarn, pnpm, pip, Pipenv, Poetry en uv inlezen
  versions.py        versies vergelijken (semver en PEP 440)
  secretscan.py      geheimen opsporen (regels van gitleaks)
  report.py          HTML en JSON
  checks/
    supply.py        A-03, C-07, F-01, F-02, F-03, F-05, F-13, B-06, C-19
    secrets.py       E-05, S-04
    agent.py         B-05, A-09
    hygiene.py       C-20
    ci.py            D-02, D-06, G-08
    github.py        R-03, R-13
    bundle.py        U-01, U-02
    code.py          C-01, C-06, C-13, E-03, E-04, E-06, H-02, H-08, P-05, U-03, U-04, U-06, U-07, W-03, W-06, S-06
    live.py          D-12, E-08, O-04, O-05, O-06, Y-01, Y-02, Y-04
  data/              checks.yaml, reference.yaml, lekkenindex, regels voor geheimen
  templates/         het rapport
tools/               lekkenindex bouwen
tests/               demo-app en regressietest
```

Een nieuwe check toevoegen: schrijf een functie met `@check("X-00")` die een `Result` teruggeeft, en zet de scan in `checks.yaml`.

## 8. Wat een ontwikkelaar moet afmaken

In volgorde van belang:

1. **Valse meldingen meten en wegwerken.** Scan 20 echte apps, laat een analist elke bevinding bevestigen of verwerpen, en meet per regel hoe vaak hij juist is. Regels onder de 80% herschrijven of op "te bevestigen" zetten.
2. **Gegevensstroomanalyse.** Voor injectie, AI-uitvoer en gevaarlijke constructies (C-01, E-04, H-02) Opengrep of Semgrep Community Edition koppelen, met eigen regels. De engine heeft een LGPL-licentie; gebruik geen regels uit het publieke Semgrep-register.
3. **Robuustheid.** Monorepo's, Yarn Berry, pnpm 9, uv; vreemde mappenstructuren; heel grote repositories; time-outs per check.
4. **Externe tools optioneel koppelen.** osv-scanner, syft en gitleaks als ze op de machine staan, en de uitkomsten vergelijken met de eigen controles.
5. **Ontbrekende stukken.**
   - Controle van cookies met een echte browser (O-04).
   - Opsporen van subdomeinen (D-12, O-06).
   - GitLab, Bitbucket en Azure DevOps (R-03, R-13).
   - CISA KEV in de lekkenindex.
   - Licenties zonder installatie (F-05).
6. **Meer talen.** Java en Kotlin, PHP, C#, Go.
7. **Niveau 2.** De 56 extra scans en een werkwijze voor de analist: bevestigen, verwerpen, ernst aanpassen met motivatie, handtekening.
8. **Het platform.** Een portaal voor klanten en accounts, met deze onderdelen:
   - versleutelde opslag met twee sleutels (klant en beheerder);
   - ondertekende rapporten met een verificatiepagina;
   - maandelijkse bewaking op de SBOM;
   - facturatie.
9. **Beveiliging van de scanner zelf.** Ondertekende releases, een SBOM van de scanner, vastgezette afhankelijkheden, geen netwerk tenzij nodig. De scanner ziet geheimen en code van klanten.

## 9. Grenzen

- Een momentopname van één versie, geen garantie.
- Geen handmatige pentest, geen functionele test, geen oordeel over de organisatie buiten de app.
- Geen wettelijke conformiteitsbeoordeling of certificering.
- Wat de scanner niet kan nagaan, staat als "Niet gescand" in het rapport en wordt nooit weggelaten.
