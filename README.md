# checkmijn.ai — scanner

Onafhankelijke controle van software die met AI gebouwd is. Een meetlat, geen mening: vaste regels, geen AI in de meting,
elke check gekoppeld aan de norm of wet waar hij uit komt (CRA, AVG, AI Act, NIS2, OWASP, ISO/IEC 27002).

**De broncode staat open ter inzage, zodat iedereen kan nagaan wat er gemeten wordt.** Zie [LICENSE.md](LICENSE.md).

## Gebruiken

**In je GitHub-repository (aanbevolen).** Zet [voorbeelden/checkmijn.yml](voorbeelden/checkmijn.yml) in je project als `.github/workflows/checkmijn.yml`. De kern:

```yaml
      - uses: Checkmijn-ai/AIScanner@main
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
| `server/` | Docker-pakket om de API te draaien op een eigen server, met installatie-instructies |
| `.github/workflows/dagversie.yml` | Bouwt elke nacht de dagversie en publiceert ze op GitHub Pages |
| `tests/` | Testproject met opzettelijke fouten, en een test van begin tot eind |

Dagversie: https://checkmijn-ai.github.io/AIScanner/latest.json (ondertekend met Ed25519, publieke sleutel in
`action/public-key.pem`).

*De scanscore is een uitslag van de scan op een bepaald moment. Ze is geen keurmerk, certificaat of garantie dat software veilig is.*
