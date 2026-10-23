# aiscan in je AI-agent (MCP)

Met MCP roept je AI-agent aiscan zelf aan, terwijl hij bouwt: Claude Code, Cursor, VS Code Copilot, Windsurf en andere agents die MCP kennen. De agent scant, leest de bevindingen met de herstelhint, herstelt en scant opnieuw tot de score goed is.

## Wat er gebeurt met je code

- **De scan draait op je eigen machine**, in een apart proces dat je agent start.
- **Het netwerk is in dat proces geblokkeerd.** Elke poging om een verbinding te maken faalt. Elke scan controleert dat en meldt het: "netwerk geblokkeerd (bevestigd)". De code kan dit proces dus niet verlaten.
- **Er gaat niets naar ons.** Het rapport komt in de map `.aiscan/` van je project. Die map negeert git automatisch. Jij beslist of je het rapport deelt.
- **Geheimen staan gemaskeerd** in alles wat de agent te zien krijgt.
- **De scan zelf gebruikt geen AI**, alleen vaste regels: dezelfde code geeft dezelfde uitkomst. Alleen je agent is AI.
- **De code van de scanner is leesbaar.** Je kunt zelf nagaan wat hij doet; het blokkeren van het netwerk staat bovenaan in `aiscan/mcp_server.py`.

## Installeren

Nodig: Python 3.11 of nieuwer en git.

```
pip install .            # in de map van aiscan
```

**Claude Code** — voor jezelf in alle projecten:

```
claude mcp add --scope user aiscan -- python -m aiscan.mcp_server
```

Of voor het hele team, via `.mcp.json` in de repository (`--scope project`):

```json
{
  "mcpServers": {
    "aiscan": { "type": "stdio", "command": "python", "args": ["-m", "aiscan.mcp_server"] }
  }
}
```

Controleren of het werkt: `claude mcp list` of `/mcp` in Claude Code. Bron: [Claude Code-documentatie over MCP](https://code.claude.com/docs/en/mcp).

**Cursor** (`.cursor/mcp.json`) en **Windsurf** gebruiken hetzelfde `mcpServers`-formaat. **VS Code** gebruikt `.vscode/mcp.json` met `"servers"` in plaats van `"mcpServers"`. Controleer het formaat in de documentatie van je editor.

## Gebruik

Zeg tegen je agent bijvoorbeeld:

- "Scan dit project met aiscan en herstel de kritieke en hoge bevindingen."
- "Draai aiscan opnieuw en vertel me de score."
- "Geef de details van scan E-04."

Of zet het in je instructies voor de agent (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`):

```
Draai na elke wijziging aiscan_scan en herstel kritieke en hoge bevindingen voor je verder gaat.
```

**De tools**

| Tool | Wat |
| --- | --- |
| `aiscan_scan` | Scant het project met de 47 scans van niveau 1. Geeft de scanscore, de belangrijkste bevindingen met bestand, regel en bewijs, en een herstelhint per scan. Schrijft het rapport naar `.aiscan/rapport.html` en `.aiscan/rapport.json`. |
| `aiscan_details` | Alle bevindingen van één scan, met normen en herstelhint. |

## De scanscore A–G

Per scan telt de zwaarste bevinding. Een bevinding die nog bevestigd moet worden, telt één niveau lager.

| Score | Zelfscan (niveau 1, deze scanner) | Keuring (vanaf niveau 2) |
| --- | --- | --- |
| A | — | Geen kritieke of hoge bevindingen, hoogstens 2 scans met een middelzware |
| B | — | Geen kritieke of hoge bevindingen |
| C | Geen kritieke of hoge bevindingen | Geen kritieke, hoogstens 2 scans met een hoge bevinding |
| D | Geen kritieke, hoogstens 2 scans met een hoge bevinding | Geen kritieke, hoogstens 5 scans met een hoge bevinding |
| E | Geen kritieke, hoogstens 5 scans met een hoge bevinding | Hoogstens 1 scan met een kritieke bevinding |
| F | Hoogstens 1 scan met een kritieke bevinding | Hoogstens 3 scans met een kritieke bevinding |
| G | 2 of meer scans met een kritieke bevinding | 4 of meer scans met een kritieke bevinding |

Een scan van niveau 1 is een zelfscan en haalt hoogstens een C (geen kritieke of hoge bevindingen); A en B zijn er alleen na een keuring. Een score komt er alleen als minstens 70% van de scans die van toepassing zijn, gescand is.

Een scan via MCP is altijd een **zelfscan**: de bouwer draaide hem zelf, op zijn eigen machine. Het rapport zegt dat er ook bij. Een **geverifieerde scan** vraagt een uitvoering die de bouwer niet kan beïnvloeden. Die volgt via de GitHub Action of door een analist.

## Voorbeeld: van G naar C

`tests/maak_demo.py` bouwt de demo-app Factuurhulp. Met `--hersteld` bouwt hij dezelfde app nadat een agent alles hersteld heeft. De eerste krijgt een G (6 scans met een kritieke bevinding), de herstelde een C, zonder bevindingen.
