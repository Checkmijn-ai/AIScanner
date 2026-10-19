# Dekking van de scans — aiscan 0.1 (concept)

Stand 17 oktober 2026 · niveau 1 · 45 scans.

| Soort | Aantal | Wat het betekent |
| --- | --- | --- |
| Automatisch | 19 | Draait volledig zonder mens. Valse meldingen blijven mogelijk tot de regels met echte apps zijn bijgesteld. |
| Deels | 16 | De scan markeert met vaste patronen; een analist bevestigt of verwerpt ("te bevestigen"). |
| Live | 8 | Alleen met `--url` en schriftelijke toestemming; getest op een lokale testserver, nog niet op echte sites. |
| Via GitHub-API | 2 | Alleen met een leestoken van de klant. |

| ID | Scan | Soort | Wat de scanner doet | Wat nog ontbreekt |
| --- | --- | --- | --- | --- |
| A-03 | SBOM in machineleesbaar formaat (SPDX of CycloneDX), automatisch bij de build gemaakt, min… | Automatisch | Maakt zelf een CycloneDX-SBOM uit de lockfiles; kijkt of de pipeline er een maakt. | Geen SPDX-uitvoer; geen andere talen dan npm en Python. |
| A-09 | AI-vermelding: vastgesteld of het product AI gebruikt (scan met vaste regels en verklaring… | Automatisch + verklaring | Herkent AI-pakketten en aanroepen van AI-diensten; schat het autonomieniveau. | Het autonomieniveau bevestigt de bouwer in de verklaring (nog geen formulier). |
| B-05 | Agentconfiguratie in de repo (instructiebestanden, regels, MCP-configuratie, prompt- en ag… | Automatisch | Leest CLAUDE.md, AGENTS.md, .cursorrules, Copilot-instructies, MCP-configuratie en agentlogs op geheimen, onveilige instructies, persoonsgegevens en MCP-risico's. | Lijst van onveilige instructies uitbreiden met echte voorbeelden; nu Engels en Nederlands. |
| B-06 | Geen verzonnen of verdachte pakketten: elke afhankelijkheid bestaat in het officiële regis… | Automatisch (offline deels) | Bekende kwaadaardige pakketten (GitHub Advisory Database), namen die op populaire pakketten lijken, pakketten die niet in de lockfile staan; online ook bestaan en leeftijd in npm en PyPI. | Offline geen controle op bestaan en leeftijd; lijst met populaire pakketten uitbreiden. |
| C-01 | Statische analyse zonder kritieke of hoge bevindingen op de vier kenmerken van ISO/IEC 505… | Deels | Regels voor eval, new Function, onveilige deserialisatie, path traversal, XXE, assert als beveiliging. | Geen volledige ISO/IEC 5055-analyse; daarvoor Opengrep of SonarQube met eigen regels koppelen. |
| C-06 | Foutafhandeling: fouten worden niet ingeslikt, gebruikers zien geen stacktraces, gedrag bi… | Deels | Lege catch en except, stacktraces naar de gebruiker, debugmodus. | Patronen; geen analyse van de gegevensstroom. |
| C-07 | Het project bouwt uit een schone checkout met één gedocumenteerde opdracht; versies zijn v… | Automatisch | Lockfile per manifest, gedocumenteerde buildopdracht. | Bouwt het project niet echt (schone checkout); dat vraagt een buildomgeving. |
| C-13 | Geen blokkerende of kritieke code smells: ongebruikte variabelen en imports, magische geta… | Deels | Verouderde API's, hardgecodeerde adressen, TODO's in beveiligingscode, onderdrukte foutmeldingen. | Geen volledige code-smellanalyse; linters (ESLint, Ruff) koppelen. |
| C-19 | Geen ongebruikte afhankelijkheden: elk pakket in het manifest wordt echt gebruikt (ongebru… | Automatisch (te bevestigen) | Directe afhankelijkheden zonder import of verwijzing in de code. | Pakketten die alleen via configuratie of plugins gebruikt worden, kunnen onterecht gemeld worden. |
| C-20 | Geen achtergebleven rommel in repository en artefact: back-upbestanden (.bak, .old, .orig)… | Automatisch | .env, dumps, sleutelbestanden, back-ups, agentgeschiedenis, logs, gebouwde uitvoer en testgegevens met echte e-mailadressen. | — |
| D-02 | Tests draaien automatisch bij elke wijziging en een falende test blokkeert de release | Automatisch | Pipeline aanwezig, voert tests uit, teststap mag niet falen. | Of de test de merge echt blokkeert, hangt af van R-03. |
| D-06 | Statische beveiligingsanalyse en afhankelijkheidsscan in de pipeline, met een drempel die … | Automatisch | SAST en scan van afhankelijkheden in de pipeline, drempel die de release blokkeert. | — |
| D-12 | Extern aanvalsoppervlak gescand: alle domeinen, subdomeinen, open poorten en publiek berei… | Live (met --url) | 27 veelgebruikte poorten op de host. | Geen opsporing van subdomeinen; geen UDP. |
| E-03 | Sessies: veilige cookies, time-outs, afmelden maakt de sessie ongeldig | Deels | Cookie-instellingen, sessiegeheimen, JWT zonder vervaldatum of controle. | Time-outs en afmelden worden niet gecontroleerd (vraagt een draaiende app). |
| E-04 | Geen injectie: geparametriseerde queries, output-encoding, geen SQL-, OS-, template- of XS… | Deels | SQL-, NoSQL-, commando- en template-injectie, XSS aan de serverkant. | Patronen per regel; geen analyse van de gegevensstroom over bestanden heen. |
| E-05 | Geen geheimen in code, configuratie of git-geschiedenis; geheimen staan in een kluis of de… | Automatisch | 221 regels voor geheimen (gebaseerd op gitleaks), ook in de volledige git-geschiedenis. | — |
| E-06 | Versleuteling: TLS 1.2 of hoger voor al het verkeer, gevoelige gegevens versleuteld opgesl… | Deels | Zwakke hashes en algoritmen, voorspelbare random, uitgeschakelde certificaatcontrole, http://, te weinig bcrypt-rondes. | TLS van de site zelf: zie Y-01. |
| E-08 | Beveiligingsheaders en configuratie: CSP, HSTS, restrictieve CORS | Live (met --url) | HSTS, CSP, X-Content-Type-Options, Referrer-Policy, clickjacking, CORS, versie in headers. | — |
| F-01 | Geen afhankelijkheden met bekende uitbuitbare kwetsbaarheden (bv. CISA KEV, EU-kwetsbaarhe… | Automatisch | Elke component vergeleken met de GitHub Advisory Database (offline index, stand 17 oktober 2026). | Geen CISA-KEV-lijst (niet bereikbaar bij het bouwen); index maandelijks bijwerken. |
| F-02 | Geen frameworks of runtimes die niet meer ondersteund worden; geen onbeheerde pakketten in… | Automatisch | Einddata van Node.js, Python, Django, Vue, jQuery; niet meer onderhouden pakketten. | Tabel handmatig bijgehouden; endoflife.date koppelen. |
| F-03 | Versies vastgezet met een lockfile en integriteitscontrole (hashes) | Automatisch | Lockfile en hashes. | — |
| F-05 | Alle licenties gekend en verenigbaar met het gebruik; geen onbedoelde copyleft | Deels | Licenties uit de lockfile of geïnstalleerde pakketten; copyleft tegenover de eigen licentie. | Zonder geïnstalleerde pakketten weinig gegevens; ScanCode of de registers koppelen. |
| F-13 | Indirecte (transitieve) afhankelijkheden worden mee gescand; bij Plus staan ze ook in de S… | Automatisch | Indirecte afhankelijkheden uit de lockfile mee gescand. | — |
| G-08 | Doorlopende bewaking van nieuwe kwetsbaarheden in afhankelijkheden via de SBOM | Automatisch | Dependabot, Renovate, Snyk of geplande scan. | De maandelijkse bewaking op de SBOM zelf is werk voor het platform. |
| H-02 | Uitvoer van het model wordt behandeld als onbetrouwbare invoer: niet rechtstreeks uitgevoe… | Deels | Volgt de uitvoer van een AI-model naar eval, shell, SQL en HTML in hetzelfde bestand. | Over bestanden heen volgen vraagt een echte gegevensstroomanalyse. |
| H-08 | Limieten op verbruik (tokens, aanvragen) tegen misbruik en onverwachte kosten | Deels | AI-aanroepen zonder limiet op tokens; rate limiting aanwezig. | — |
| O-04 | Geen cookies of trackers vóór toestemming: de scan bezoekt de site zonder te klikken en no… | Live (met --url) | Trackingcookies van de server vóór toestemming; trackingscripts zonder toestemmingsbeheer. | Cookies die JavaScript plaatst: controle met een echte browser volgt. |
| O-05 | De site zelf is veilig: TLS, beveiligingsheaders, CMS en plugins op een ondersteunde versi… | Live (met --url) | .git, .env, phpMyAdmin, serverstatus, beheerpagina's, CMS-versie; TLS en headers via Y-01 en E-08. | Versies van plugins worden niet nagekeken. |
| O-06 | Domein en e-mail beschermd tegen misbruik: SPF, DKIM en DMARC ingesteld, geen overneembare… | Live (met --url) | SPF, DMARC, DKIM (gangbare selectors), DNSSEC. | Geen opsporing van overneembare subdomeinen. |
| P-05 | Inkomende webhooks en berichten worden gecontroleerd (handtekening, herkomst); uitgaande v… | Deels | Webhooks zonder controle van de handtekening; uitgaande verzoeken naar adressen uit invoer (SSRF). | — |
| R-03 | Branchstrategie vastgelegd; hoofdbranch beschermd: geen directe of geforceerde push, verpl… | Via GitHub-API (met token) | Branchbeveiliging of rulesets: review, geen force-push, verplichte pipeline. | GitLab, Bitbucket en Azure DevOps volgen. |
| R-13 | Repository-instellingen: geheimenscanning en afhankelijkheidswaarschuwingen aan, geen onbe… | Via GitHub-API (met token) | Geheimenscanning, push protection, waarschuwingen voor kwetsbaarheden, publieke repository. | Langlevende tokens zijn niet via de API te zien. |
| S-04 | Geen geheimen of API-sleutels in de app zelf | Automatisch | Geheimen in de code van de mobiele app. | Geen analyse van de gebouwde app (APK/IPA). |
| S-06 | SDK's van derden (analyse, advertenties, crashrapporten) geïnventariseerd; tracking pas na… | Deels | SDK's voor analyse en reclame, toestemmingsvraag. | — |
| U-01 | Geen geheimen, API-sleutels of interne adressen in de JavaScript-bundel | Automatisch | Geheimen en interne adressen in de gebouwde frontend; geheime variabelen die naar de browser gaan; AI-sleutels in de browser. | Gebouwde uitvoer moet in de map staan (scan na de build). |
| U-02 | Source maps en debugmodus niet publiek in productie | Automatisch | Source maps in de gebouwde uitvoer en in de buildconfiguratie. | — |
| U-03 | Sessietokens en gevoelige gegevens niet in localStorage of sessionStorage; cookies met Htt… | Automatisch | Tokens in localStorage, sessionStorage en document.cookie. | — |
| U-04 | Bescherming tegen CSRF en clickjacking (frame-ancestors) | Deels | Clickjacking-bescherming en CSRF-bescherming in de code; csrf_exempt in Django. | Bevestigen op de live site (E-08). |
| U-06 | Scripts van derden (analyse, chat, advertenties) geïnventariseerd, met toestemming waar no… | Deels | Externe scripts, integriteitscontrole (SRI), trackers zonder toestemmingsbeheer, CSP. | — |
| U-07 | Geen gevaarlijke DOM-functies met gebruikersinvoer (innerHTML, eval); berichten tussen ven… | Deels | innerHTML, dangerouslySetInnerHTML, v-html, document.write, postMessage zonder herkomstcontrole. | — |
| W-03 | Bestandsopslag (bv. S3, Blob) privé, toegang via kortlevende ondertekende links; uploads g… | Deels | Publieke buckets, uploads in publieke mappen. | Cloudconfiguratie zelf (bucketbeleid) vraagt toegang tot de cloud. |
| W-06 | Limieten op middelen: time-outs, maximale grootte van verzoeken en uploads, paginering, be… | Deels | Time-outs op uitgaande verzoeken, limieten op uploads en verzoekgrootte. | — |
| Y-01 | TLS juist ingesteld: alleen TLS 1.2 en 1.3, sterke cipher suites met forward secrecy, geld… | Live (met --url) | TLS-versies, zwakke ciphers, certificaat en vervaldatum, HSTS. | TLS 1.0/1.1 testen hangt af van de OpenSSL-versie van de machine. |
| Y-02 | Geen onversleutelde protocollen voor gegevens of beheer: geen HTTP behalve doorverwijzing,… | Live (met --url) | HTTP stuurt door naar HTTPS; FTP, Telnet, LDAP, MQTT, POP3 en IMAP zonder TLS. | — |
| Y-04 | Verouderde protocolversies uit: SSH alleen versie 2 met sterke algoritmen en sleutels, SMB… | Live (met --url) | SSH versie 1, RDP en SMB publiek. | Algoritmen en sleutels van SSH vragen een SSH-audit. |
