# checkmijn.ai — scanner

Onafhankelijke controle van software die met AI gebouwd is. Een meetlat, geen mening: vaste regels, geen AI in de meting,
elke check gekoppeld aan de norm of wet waar hij uit komt (CRA, AVG, AI Act, NIS2, OWASP, ISO/IEC 27002).

**De broncode staat open ter inzage, zodat iedereen kan nagaan wat er gemeten wordt.** Zie [LICENSE.md](LICENSE.md).

## Gebruiken

**In je GitHub-repository (aanbevolen, ook voor Lovable, Bolt en v0).** Zet dit in `.github/workflows/checkmijn.yml`:

```yaml
name: checkmijn.ai
on:
  push:
    branches: [main]
  workflow_dispatch: {}
  schedule:
    - cron: "30 4 * * 1"   # elke maandag
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8  # v5.0.0
        with:
          fetch-depth: 0          # volledige geschiedenis: ook oude geheimen worden gevonden
      - uses: klankenreis/checkmijn-scanner@main
        with:
          insturen: "false"       # "true" = bewijsbestand (zonder code) inleveren voor een scorepagina
          faal-bij: nooit         # of: kritiek, hoog
```

De uitslag staat in de samenvatting van de run. Het volledige rapport is een artefact van de run en blijft in GitHub.

**Met een AI-agent met terminal** (Claude Code, Cursor, Copilot): *"Volg de instructie op checkmijn.ai/scan.md voor dit project."*

**Lokaal:** `python -m aiscan PAD --offline` (Python 3.11+, `pip install -r requirements.txt`).

## Wat er in deze repository staat

| Map | Wat |
| --- | --- |
| `aiscan/` | De scanner: 45 checks van niveau 1, regels voor geheimen, lekkenindex (GitHub Advisory Database) |
| `action.yml`, `action/` | De GitHub Action |
| `platform/` | Nachtelijke bouw van de dagversie, catalogus van checks, API voor bewijs en scorepagina's |
| `server/` | Docker-pakket om de API te draaien op een eigen server, met installatie-instructies |
| `.github/workflows/dagversie.yml` | Bouwt elke nacht de dagversie en publiceert ze op GitHub Pages |
| `tests/` | Testproject met opzettelijke fouten, en een test van begin tot eind |

Dagversie: https://klankenreis.github.io/checkmijn-scanner/latest.json (ondertekend met Ed25519, publieke sleutel in
`action/public-key.pem`).

*De scanscore is een uitslag van de scan op een bepaald moment. Ze is geen keurmerk, certificaat of garantie dat software veilig is.*
