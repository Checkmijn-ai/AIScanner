# aiscan-platform — dagversie, instructie voor agents en API

Dit is het deel dat op jouw server draait. De scanner zelf staat in `../aiscan/`.

```
Elke nacht (cron)                       Overdag (agent van de klant)                    Jouw site
─────────────────                       ────────────────────────────                    ─────────
build_daily.py                          leest jouwsite.be/aiscan/scan.md
 ├ lekkendatabank bijwerken (GHSA)      ├ downloadt aiscan-JJJJ-MM-DD.pyz
 ├ catalogus controleren + changelog    ├ controleert het controlegetal
 ├ scanner inpakken (.pyz)              ├ aiscan.pyz sessie  ─────────────────────────▶ POST /api/v1/sessie
 ├ controlegetal + Ed25519-handtekening ├ aiscan.pyz PROJECT --offline --bewijs (lokaal, zonder netwerk)
 └ publiceren: latest.json, scan.md …   ├ herstelt, scant opnieuw
                                        └ aiscan.pyz inleveren bewijs.json ──────────▶ POST /api/v1/resultaat
                                                                                         ├ controleert alles
                                                                                         └ /score/<id> + badge
```

## Wat waar komt

| Pad op de site | Wat | Wie leest het |
| --- | --- | --- |
| `/aiscan/scan.md` | Instructie voor AI-agents, elke dag vernieuwd met het controlegetal van die dag | Agents |
| `/aiscan/aiscan-JJJJ-MM-DD.pyz` | De scanner van die dag, één bestand, met de lekkendatabank erin | Agents |
| `/aiscan/latest.json` | Manifest van vandaag, ondertekend met Ed25519 | Agents, controles |
| `/aiscan/public-key.pem` | Publieke sleutel om het manifest na te kijken | Iedereen |
| `/aiscan/checks.json` | Alle checks met hun vaste nummer, versie en status | Iedereen |
| `/aiscan/changelog.json` | Wat er wanneer veranderde aan de checks | Iedereen |
| `/aiscan/versies.json` | Gepubliceerde dagversies met controlegetal (de API gebruikt dit) | API |
| `api.jouwsite.be` | De API en de scorepagina's | Agents, bezoekers |

De sitebouwer hoeft alleen een link te zetten naar `/aiscan/scan.md` en de bestanden in `/aiscan/` ongewijzigd te serveren. De API draait apart (een kleine server of container), bij voorkeur op een subdomein.

## Installeren op een server (eenmalig)

1. Python 3.11+, git en sqlite3 op de server. Daarna: `pip install -r requirements.txt cryptography flask gunicorn`.
2. Sleutelpaar maken: `python platform/sleutels.py /opt/aiscan/sleutels`. Bewaar een kopie van `dagversie.pem` offline; nooit in git.
3. Eerste dagversie: de regel uit `crontab.txt` één keer met de hand draaien. De eerste keer kloont hij de GitHub Advisory Database (±500 MB).
4. Cron instellen met `crontab.txt`, of GitHub Actions met `github/dagversie.yml`.
5. De API starten achter HTTPS (bv. nginx of Caddy):
   ```
   AISCAN_PUBLIC=/var/www/jouwsite/aiscan AISCAN_DB=/var/lib/aiscan/aiscan.db AISCAN_SITE=https://api.jouwsite.be \
   gunicorn -w 2 -b 127.0.0.1:5000 --chdir /opt/aiscan/platform api:app
   ```

Instellingen (omgevingsvariabelen): `AISCAN_PUBLIC`, `AISCAN_DB`, `AISCAN_SITE`, `AISCAN_MAX_LEEFTIJD_DAGEN` (standaard 7), `AISCAN_SCORE_GELDIG_DAGEN` (standaard 30), `AISCAN_LIMIET_PER_UUR` (standaard 60 per IP).

## Checks en nummering

`python platform/catalogus.py lijst | controleer | nieuw | wijzig | vervallen` — zie de uitleg bovenaan `catalogus.py`. Kort:
- Een ID hoort voor altijd bij één controle; een vervallen ID wordt nooit hergebruikt.
- Een nieuwe check krijgt het volgende vrije nummer in zijn domein, rekening houdend met alle ID's van de volledige norm (niveau 1–4).
- Een inhoudelijke wijziging verhoogt de versie van de check. De nacht erna staat ze in `changelog.json`.

## Wat de API controleert, en wat niet

Bij elk bewijs:
- de sessiecode bestaat, is hoogstens 2 uur oud en wordt maar één keer aanvaard;
- de scanner is een gepubliceerde dagversie (controlegetal) van hoogstens 7 dagen oud;
- de regelset hoort bij die dagversie;
- precies de checks van die dagversie zitten erin, met kloppende statussen;
- de score klopt: de API rekent ze zelf opnieuw uit.

Wat de API niet kan uitsluiten: dat iemand op zijn eigen machine knoeit met de scanner of het bewijs. Daarom is elke score via deze route een **Zelfcontrole**, en de scorepagina zegt dat.

**Volgende stap voor een geverifieerde scan:** dezelfde scan in GitHub Actions of GitLab CI, met een attestation van het platform (GitHub: artifact attestations op basis van Sigstore). De API kijkt dan na dat de workflow, de commit en de uitslag bij elkaar horen, en zet de soort op "Geverifieerde scan". Dat is nog te bouwen.

## Privacy

- De API ontvangt nooit code, bestandsnamen of bevindingen: alleen per check de status, de zwaarste ernst en het aantal, plus versie, commit en een controlegetal over de code.
- Elke scorepagina heeft een willekeurige link; de eigenaar beslist met wie hij ze deelt. De projectnaam staat erop.
- Logs van de webserver bevatten IP-adressen: neem dit op in je privacyverklaring.

## Testen

`python tests/test_platform.py` bouwt een dagversie, start de API, volgt `scan.md` zoals een agent, levert het bewijs in en probeert te knoeien (score aanpassen, sessiecode hergebruiken, onbekende scanner). Alle pogingen tot knoeien moeten geweigerd worden.
