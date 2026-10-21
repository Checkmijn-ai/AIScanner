# checkmijn.ai online zetten

Alles draait op één server in de EU: de website, de API, de scorepagina's en de versleutelde rapporten. GitHub zet
elke wijziging er automatisch op.

| Adres | Wat | Uit de tak |
| --- | --- | --- |
| https://checkmijn.ai | Website, rapporten, scan.md | `main` |
| https://api.checkmijn.ai | API, scorepagina's en badges | `main` |
| https://test.checkmijn.ai | Testversie, om wijzigingen eerst te bekijken | `test` |
| https://checkmijn-ai.github.io/AIScanner | De dagversie van de scanner (elke nacht) | GitHub Pages |

---

## 1. De server aanmaken (±10 minuten)

1. Maak bij **Hetzner Cloud** een project aan en kies **Add Server**:
   - Location: **Nuremberg** of **Falkenstein** (Duitsland)
   - Image: **Ubuntu 24.04**
   - Type: **CX32** (4 vCPU, 8 GB), of CX22 als het krap mag
   - **SSH keys → Add SSH key:** plak de publieke sleutel `checkmijn-uitrol.pub` die je van Claude kreeg
   - Name: `checkmijn`
2. **Firewalls → Create Firewall:** sta binnenkomend alleen toe: TCP 22, TCP 80, TCP 443 en UDP 443. Koppel de
   firewall aan de server.
3. Noteer het **IPv4-adres**, bv. `203.0.113.10`.

## 2. GitHub de sleutel geven

In **Checkmijn-ai/AIScanner → Settings → Secrets and variables → Actions → New repository secret**:

| Name | Secret |
| --- | --- |
| `UITROL_HOST` | het IPv4-adres van de server |
| `UITROL_SLEUTEL` | de volledige inhoud van `checkmijn-uitrol` (de privésleutel), met de regels BEGIN en END |

Bewaar daarna een kopie van `checkmijn-uitrol` in je wachtwoordbeheerder en verwijder het bestand uit je downloads.

## 3. DNS in Cloudflare

Ga naar **checkmijn.ai → DNS → Records**. Zet bij elk record de proxy op **DNS only** (grijze wolk), zodat de server
zelf een certificaat kan halen.

| Type | Name | Content |
| --- | --- | --- |
| A | `@` | het IPv4-adres |
| A | `www` | het IPv4-adres |
| A | `api` | het IPv4-adres |
| A | `test` | het IPv4-adres |

Staan er nog records van Lovable voor `@` of `www`, verwijder die dan eerst.

**E-mail** (Email → Email Routing): maak twee adressen die doorsturen naar je eigen mailbox:
`hallo@checkmijn.ai` (contact op de site) en `security@checkmijn.ai` (meldingen van kwetsbaarheden).
Voeg ook het DMARC-record toe: TXT `_dmarc` met `v=DMARC1; p=reject; rua=mailto:security@checkmijn.ai`.
Zet *DNSSEC* aan bij DNS → Settings.

## 4. De eerste keer uitrollen

Ga naar **Actions → Uitrollen → Run workflow** en kies `main`. De eerste keer installeert de workflow ook Docker,
automatische beveiligingsupdates en een firewall op de server. Dat duurt ±5 minuten.

In de log van de stap *SSH klaarzetten* staat een regel die begint met het IP-adres en `ssh-ed25519`. Zet die regel
als secret **`UITROL_HOSTKEY`**. Zo kan niemand zich later als jouw server voordoen.

Daarna gaat het vanzelf:
- een wijziging op `main` staat binnen een paar minuten op checkmijn.ai;
- een wijziging op `test` staat op test.checkmijn.ai.

## Nakijken

- https://checkmijn.ai → de website
- https://checkmijn.ai/scan.md → de instructie van vandaag
- https://api.checkmijn.ai/api/v1/versie → de dagversie
- https://test.checkmijn.ai → de testversie (zodra de tak `test` bestaat)

## Met de hand (als het nodig is)

```
ssh root@<ip>
cd /opt/checkmijn/server
docker compose ps          # wat draait er
docker compose logs -f live   # de log van de site en de API
bash uitrol.sh main        # opnieuw uitrollen
```
