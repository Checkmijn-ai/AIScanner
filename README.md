# checkmijn.ai — scanner

Onafhankelijke controle van software die met AI gebouwd is. Een meetlat, geen mening: vaste regels, geen AI in de meting,
elke check gekoppeld aan de norm of wet waar hij uit komt (CRA, AVG, AI Act, NIS2, OWASP, ISO/IEC 27002).

**Open source onder de EUPL-1.2.** Iedereen kan nagaan wat er gemeten wordt, en de scanner zelf draaien. Zie [LICENSE.md](LICENSE.md). De lijst van checks (de norm) staat in [`norm/checks.yaml`](norm/checks.yaml), onder CC BY 4.0.

## Gebruiken

**In je GitHub-repository (aanbevolen).** Zet [voorbeelden/checkmijn.yml](voorbeelden/checkmijn.yml) in je project als `.github/workflows/checkmijn.yml`. De kern:

```yaml
      - uses: Checkmijn-ai/AIScanner@v1   # vrijgegeven versie; of de volledige commit voor de strengste controle
        with:
          rapport-in-repo: auto   # privé-repository: rapport in .checkmijn/RAPPORT.md
          insturen: "false"       # "true" = bewijsbestand (zonder code) inleveren voor een scorepagina
          faal-bij: nooit         # of: kritiek, hoog
```

De uitslag staat in de samenvatting van de run. Het volledige rapport is een artefact van de run en blijft in GitHub.

**Met Lovable, Bolt of v0 (geen terminal):** zie [LOVABLE-BOLT-V0.md](LOVABLE-BOLT-V0.md). De scan draait in GitHub, en je bouwtool leest het rapport uit `.checkmijn/RAPPORT.md` en herstelt de bevindingen.

**Met een AI-agent met terminal** (Claude Code, Cursor, Copilot): *"Volg de instructie op checkmijn.ai/scan.md voor dit project."*

**Lokaal:** `python -m aiscan PAD --offline` (Python 3.11+, `pip install -r requirements.txt`).

## Wat er in deze repository staat

| Map | Wat |
| --- | --- |
| `aiscan/` | De scanner: 45 checks van niveau 1, regels voor geheimen, lekkenindex (GitHub Advisory Database) |
| `action.yml`, `action/` | De GitHub Action |
| `voorbeelden/checkmijn.yml` | De workflow om in je project te zetten |
| `platform/` | Nachtelijke bouw van de dagversie, catalogus van checks, API voor bewijs en scorepagina's |
| `platform/website.py`, `platform/templates/site/`, `platform/static/` | De website checkmijn.ai (zelfde app als de API) |
| `server/` | Docker, Caddy en `uitrol.sh`: website en API op een eigen server in de EU, met installatie-instructies |
| `.github/workflows/uitrollen.yml` | Zet `main` op checkmijn.ai en `test` op test.checkmijn.ai |
| `.github/workflows/dagversie.yml` | Bouwt elke nacht de dagversie en publiceert ze op GitHub Pages |
| `tests/` | Testproject met opzettelijke fouten, en een test van begin tot eind |

Dagversie: https://checkmijn-ai.github.io/AIScanner/latest.json (ondertekend met Ed25519, publieke sleutel in
`action/public-key.pem`).

*De scanscore is een uitslag van de scan op een bepaald moment. Ze is geen keurmerk, certificaat of garantie dat software veilig is.*
