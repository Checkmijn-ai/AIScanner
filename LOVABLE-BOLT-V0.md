# Scannen met Lovable, Bolt of v0

Deze tools hebben geen terminal, dus de scanner kan er niet in draaien. Daarom draait hij in **GitHub**, op elke wijziging. Je bouwtool leest daarna het rapport en herstelt de bevindingen.

- De code verlaat GitHub niet.
- Het opgemaakte rapport bewaren we **versleuteld**. De sleutel zit alleen in jouw persoonlijke link (na `#`), dus wij kunnen het niet lezen. Wil je dat niet, zet dan `rapport-link: "false"` in het workflowbestand.
- Het rapport komt alleen in je project als je repository **privé** is. In een openbare repository zou iedereen de lekken lezen.

## In drie stappen

**1. Koppel je project aan GitHub,** met een **privé**-repository.
- Lovable: de GitHub-knop, of de projectinstellingen → GitHub → Connect.
- Bolt en v0: de GitHub-koppeling in het menu.

**2. Plak dit één keer in de chat van je bouwtool:**

```
Volg de instructie op https://checkmijn.ai/scan.md, route B (via GitHub), voor dit project.
Maak het bestand .github/workflows/checkmijn.yml precies zoals daar staat, en verander verder niets.
De scan draait daarna in GitHub. Typ ik "verder", lees dan .checkmijn/RAPPORT.md opnieuw en toon mij
de score en de bevindingen, zonder iets te veranderen. Vraag één keer of je mag herstellen; mijn "ja"
geldt voor de hele sessie: herstel dan Kritiek, Hoog en Middel in één ronde, en na elke nieuwe scan
meteen wat er nog echt openstaat. Wijzig .checkmijn/ en het workflowbestand nooit, en geef zelf geen score.
```

Werkt de link nog niet? Gebruik dan https://checkmijn-ai.github.io/AIScanner/scan.md.

**3. Typ na 2 à 3 minuten: `verder`.** Zo lang duurt de scan in GitHub. Je bouwtool toont de score en de bevindingen en vraagt of hij mag herstellen. Zeg `ja`, en typ na het herstel weer `verder` voor de nieuwe score. Is de scan nog niet klaar, dan zegt je bouwtool dat; typ dan een minuut later opnieuw `verder`.

Na elke wijziging scant GitHub opnieuw en wordt het rapport bijgewerkt. In het rapport staat een tabel met alle scans, zodat je het verloop ziet (bv. G → C → B).

**Het volledige rapport (HTML)** vind je via de link bovenaan `RAPPORT.md`: de run in GitHub, onder *Artifacts*.

## Lekkenwacht: een seintje bij een nieuw lek

Met het nieuwste workflowbestand scant GitHub je project **elke dag**. Is er een nieuw kritiek of hoog lek in een van je pakketten, dan krijg je een **issue** in je repository, en GitHub mailt je. Is alles opgelost, dan sluit het issue vanzelf. Er gaat niets naar checkmijn.ai.

- **Nieuw project?** Dan staat de lekkenwacht al aan: hij zit in het bestand van stap 2.
- **Al eerder gescand (voor 21 oktober 2026)?** Plak dan in je bouwtool:

```
Zet de lekkenwacht van checkmijn.ai aan: volg https://checkmijn.ai/scan.md, onderdeel Lekkenwacht.
Vervang .github/workflows/checkmijn.yml precies door de nieuwste versie, en verander verder niets.
```

**Werkt het?** Ga in GitHub naar *Actions → checkmijn.ai* en open de laatste run: onderaan de samenvatting staat een regel die begint met "Lekkenwacht". Zet bij *Settings → Notifications* e-mail aan, zodat je de issues ook echt ziet.

## Weigert je bouwtool het bestand te maken?

Maak het dan zelf, in GitHub:
1. Ga naar je repository → **Add file → Create new file**.
2. Naam: `.github/workflows/checkmijn.yml`.
3. Plak de inhoud van [voorbeelden/checkmijn.yml](voorbeelden/checkmijn.yml), en klik op **Commit changes**.

## Waar zie ik de uitslag?

| Waar | Wat |
| --- | --- |
| De persoonlijke link bovenaan `RAPPORT.md` | Het opgemaakte rapport, zoals een keurder het ziet. Je kunt het ook downloaden. Niet aan een account gekoppeld: 90 dagen bewaard |
| `.checkmijn/RAPPORT.md` in je project | Score en alle bevindingen, met bestand, regel en hoe je ze oplost (alleen in een privé-repository) |
| GitHub → **Actions** → *checkmijn.ai* → de laatste run | Score en een overzicht, plus het volledige rapport onder *Artifacts* |

## Hoe weet ik dat het een echte scan is?

- De scan draait de **ondertekende dagversie** van de scanner. Die controleert de handtekening en het controlegetal, en scant zonder netwerk.
- Je bouwtool geeft geen eigen oordeel. Het rapport komt van de scanner en wordt bij elke scan overschreven.
- Dezelfde code geeft altijd dezelfde uitslag.

Met een tool die wel een terminal heeft, zoals Replit, Claude Code, Cursor of Copilot, kun je ook **route A** volgen. De scanner draait dan op je eigen machine.

*De scanscore is een uitslag van de scan op een bepaald moment. Ze is geen keurmerk, certificaat of garantie dat software veilig is.*
