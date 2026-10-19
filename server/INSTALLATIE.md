# checkmijn.ai online zetten

Dit zijn drie onderdelen, elk op een eigen plek:

| Onderdeel | Adres | Waar |
| --- | --- | --- |
| Website | checkmijn.ai | Lovable (publiceren vanuit Lovable) |
| Dagversie van de scanner | klankenreis.github.io/checkmijn-scanner | GitHub Pages, elke nacht automatisch |
| API voor scorepagina's en badges | api.checkmijn.ai | Je eigen server in de EU, met dit pakket |

---

## 1. GitHub (eenmalig, ±5 minuten)

In de repository **klankenreis/checkmijn-scanner**:

1. **Pages aanzetten.** Ga naar *Settings → Pages* en kies bij *Source* "**GitHub Actions**".
2. **De sleutel om de dagversie te ondertekenen.** Ga naar *Settings → Secrets and variables → Actions → New repository secret*:
   - Name: `DAGVERSIE_SLEUTEL`
   - Secret: de volledige inhoud van het bestand `dagversie.pem` dat je gekregen hebt, inclusief de regels met BEGIN en END.

   Bewaar daarna een kopie van dat bestand offline, bv. in je wachtwoordbeheerder, en verwijder het uit je downloads.
3. **De eerste dagversie bouwen.** Ga naar *Actions → Dagversie → Run workflow*. Na ±5 minuten staat de dagversie op
   https://klankenreis.github.io/checkmijn-scanner/latest.json. Daarna gebeurt dit elke nacht om 03:15.

---

## 2. Server voor de API (±20 minuten)

Een kleine server is genoeg, bv. **Hetzner Cloud CX22** (±€5 per maand), in Falkenstein, Neurenberg of Helsinki. Een
gelijkaardige server bij Scaleway, OVHcloud of Combell kan ook.

1. **Server maken.** Kies *Ubuntu 24.04* en voeg je SSH-sleutel toe. Noteer het IPv4-adres, bv. `203.0.113.10`.
2. **Firewall** (in het Hetzner-paneel, *Firewalls*). Sta alleen poort 22 (SSH), 80 en 443 toe.
3. **Inloggen en installeren:**

   ```
   ssh root@203.0.113.10
   apt update && apt -y upgrade
   curl -fsSL https://get.docker.com | sh
   git clone https://github.com/klankenreis/checkmijn-scanner /opt/checkmijn
   ```

4. **Eerst DNS instellen** (stap 3 hieronder), en dan pas starten:

   ```
   cd /opt/checkmijn/server
   docker compose up -d --build
   ```

   Caddy haalt automatisch een certificaat. Na een minuut moet https://api.checkmijn.ai/api/v1/versie de dagversie tonen.

5. **Bijwerken**, als er een nieuwe versie van de API is:

   ```
   cd /opt/checkmijn && git pull && cd server && docker compose up -d --build
   ```

6. **Automatische beveiligingsupdates** van Ubuntu: `apt -y install unattended-upgrades`.

---

## 3. DNS in Cloudflare

Ga in Cloudflare naar je domein **checkmijn.ai → DNS → Records**.

### API

| Type | Name | Content | Proxy status |
| --- | --- | --- | --- |
| A | `api` | het IPv4-adres van je server | **DNS only** (grijze wolk) |

Zet de proxy op "DNS only", zodat Caddy zelf een certificaat kan halen. Later kan de oranje wolk aan, met *SSL/TLS →
Full (strict)*.

### Website (Lovable)

1. Ga in Lovable naar je project, dan *Settings → Domains → Connect domain*, en vul `checkmijn.ai` in.
2. Lovable toont de records die je moet aanmaken, meestal A-records voor `@` en `www` en een TXT-record om het domein te
   bevestigen. **Neem ze exact over in Cloudflare**, met de proxy op **DNS only** (grijze wolk).
3. Wacht tot Lovable "Active" toont. Dat duurt meestal minuten, soms tot een paar uur.

### E-mail (ook als je nog geen e-mail verstuurt)

Wij controleren dit bij klanten (check O-06), dus ons eigen domein moet het ook halen.

**Meldadres security@checkmijn.ai:**
1. Ga naar *Email → Email Routing*, zet het aan en laat Cloudflare de MX- en SPF-records toevoegen.
2. Maak een regel: `security@checkmijn.ai` → je eigen mailadres.

**DMARC:** voeg dit TXT-record toe.

| Type | Name | Content |
| --- | --- | --- |
| TXT | `_dmarc` | `v=DMARC1; p=reject; rua=mailto:security@checkmijn.ai` |

Verstuur je later mail vanaf checkmijn.ai, bv. via Google Workspace of Microsoft 365, voeg dan hun SPF- en DKIM-records toe.

**Algemeen:**
- Zet *DNSSEC* aan bij *DNS → Settings*.
- Zet de domeinvergrendeling aan bij je registrar, als die het aanbiedt.
- Zet tweestapsverificatie aan op je Cloudflare-account.

---

## Nakijken

- https://klankenreis.github.io/checkmijn-scanner/latest.json → toont de dagversie met `"handtekening"`.
- https://api.checkmijn.ai/api/v1/versie → toont hetzelfde.
- https://checkmijn.ai/scan.md → toont de instructie van vandaag (na het samenvoegen van de pull request van de website).
- Scan je eigen site: `python -m aiscan . --url https://checkmijn.ai` → het doel is minstens een B.
