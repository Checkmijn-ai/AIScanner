# Gebruikte bronnen en licenties

| Onderdeel | Bron | Licentie | Gebruik |
| --- | --- | --- | --- |
| Regels voor geheimen (`aiscan/data/secret_rules.json`) | gitleaks, github.com/gitleaks/gitleaks | MIT | Patronen omgezet naar Python; licentietekst hieronder |
| Lekkenindex (`aiscan/data/advisories.json.gz`) | GitHub Advisory Database, github.com/github/advisory-database | CC-BY 4.0 | Samengevat tot npm en PyPI; bronvermelding in elk rapport |
| PyYAML, Jinja2, requests, packaging | PyPI | MIT / BSD / Apache-2.0 | Bibliotheken |

Geen Semgrep-regels uit het publieke register: die mogen niet zomaar commercieel als dienst gebruikt worden.
Geen GPL-tools in de scanner zelf.

## gitleaks — MIT License

MIT License

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Meegeleverd in de dagversie (.pyz)

Het scannerbestand bevat deze pure-Python-bibliotheken, ongewijzigd, zodat er bij de klant niets geïnstalleerd hoeft te worden. Hun licentiebestanden zitten in de map `_vendor` van het bestand.

| Bibliotheek | Licentie |
| --- | --- |
| PyYAML | MIT |
| Jinja2, MarkupSafe | BSD-3-Clause |
| packaging | Apache-2.0 of BSD-2-Clause |
| requests | Apache-2.0 |
| urllib3, charset-normalizer | MIT |
| idna | BSD-3-Clause |
| certifi | MPL-2.0 (ongewijzigd meegeleverd) |
