# Scannen met Lovable, Bolt of v0

Deze tools hebben geen terminal, dus de scanner kan er niet in draaien. Daarom draait hij in **GitHub**, op elke wijziging. Je bouwtool leest daarna het rapport en herstelt de bevindingen.

- De code verlaat GitHub niet. Er gaat niets naar checkmijn.ai, tenzij je dat later zelf aanzet.
- Het rapport komt alleen in je project als je repository **privé** is. In een openbare repository zou iedereen de lekken lezen.

## In drie stappen

**1. Koppel je project aan GitHub,** met een **privé**-repository.
- Lovable: de GitHub-knop, of de projectinstellingen → GitHub → Connect.
- Bolt en v0: de GitHub-koppeling in het menu.

**2. Plak dit in de chat van je bouwtool:**

```
Volg de instructie op https://checkmijn.ai/scan.md, route B (via GitHub), voor dit project.
Maak het bestand .github/workflows/checkmijn.yml precies zoals daar staat, en verander verder niets.
Geef zelf geen score: de scan gebeurt in GitHub.
```

Werkt de link nog niet? Gebruik dan https://checkmijn-ai.github.io/AIScanner/scan.md.

**3. Wacht een paar minuten**, en plak dan:

```
Lees .checkmijn/RAPPORT.md en herstel de bevindingen, eerst Kritiek, dan Hoog, dan Middel.
Wijzig .checkmijn/ en .github/workflows/checkmijn.yml niet, en geef zelf geen score.
```

Na elke wijziging scant GitHub opnieuw en wordt het rapport bijgewerkt. Herhaal stap 3 tot de bevindingen weg zijn.

## Weigert je bouwtool het bestand te maken?

Maak het dan zelf, in GitHub:
1. Ga naar je repository → **Add file → Create new file**.
2. Naam: `.github/workflows/checkmijn.yml`.
3. Plak de inhoud van [voorbeelden/checkmijn.yml](voorbeelden/checkmijn.yml), en klik op **Commit changes**.

## Waar zie ik de uitslag?

| Waar | Wat |
| --- | --- |
| `.checkmijn/RAPPORT.md` in je project | Score en alle bevindingen, met bestand, regel en hoe je ze oplost (alleen in een privé-repository) |
| GitHub → **Actions** → *checkmijn.ai* → de laatste run | Score en een overzicht, plus het volledige rapport onder *Artifacts* |

## Hoe weet ik dat het een echte scan is?

- De scan draait de **ondertekende dagversie** van de scanner. Die controleert de handtekening en het controlegetal, en scant zonder netwerk.
- Je bouwtool geeft geen eigen oordeel. Het rapport komt van de scanner en wordt bij elke scan overschreven.
- Dezelfde code geeft altijd dezelfde uitslag.

Met een tool die wel een terminal heeft, zoals Replit, Claude Code, Cursor of Copilot, kun je ook **route A** volgen. De scanner draait dan op je eigen machine.

*De scanscore is een uitslag van de scan op een bepaald moment. Ze is geen keurmerk, certificaat of garantie dat software veilig is.*
