# Scannen in GitLab, Bitbucket of Azure DevOps

De scan werkt ook buiten GitHub. Het principe is hetzelfde:

- de scan draait **alleen als jij hem start**, nooit vanzelf;
- de scan leest je project en verandert niets; de code verlaat je pipeline niet;
- het scanscript en de sleutel komen van één **vaste versie** en worden gecontroleerd met een controlegetal; de scanner van de dag wordt daarna gecontroleerd op handtekening en controlegetal. Klopt iets niet, dan stopt de scan;
- het rapport (`rapport.html` en `samenvatting.md`) staat bij de artefacten van de run, 30 dagen lang.

| Platform | Bestand | Zet het in je project als | Starten |
| --- | --- | --- | --- |
| GitLab | [voorbeelden/gitlab-ci.yml](voorbeelden/gitlab-ci.yml) | `.gitlab-ci.yml` (of voeg de job toe) | Build → Pipelines → **Run pipeline** |
| Bitbucket | [voorbeelden/bitbucket-pipelines.yml](voorbeelden/bitbucket-pipelines.yml) | `bitbucket-pipelines.yml` (of voeg het blok `custom` toe) | Pipelines → **Run pipeline** → `custom: checkmijn` |
| Azure DevOps | [voorbeelden/azure-pipelines.yml](voorbeelden/azure-pipelines.yml) | `azure-pipelines-checkmijn.yml`, als nieuwe pipeline | Pipelines → de pipeline → **Run pipeline** |

**Waar staat de uitslag?** Open de run en download het artefact `checkmijn-rapport`. Daarin staan `rapport.html` (het volledige rapport) en `samenvatting.md` (score en overzicht).

**Wat er (nog) niet kan buiten GitHub**

- Geen versleutelde rapportlink en geen meetellen in de statistiek: daarvoor gebruiken we het ondertekende token van GitHub.
- Geen rapport terug in het project voor een AI-bouwtool.
- De checks R-03 en R-13 (instellingen van de repository) lezen de instellingen via de GitHub-koppeling. Op een ander platform zijn dat handmatige checks: de klant laat ze zien.

**Klaar?** Haal het bestand weer weg. Wil je later opnieuw scannen, haal dan de nieuwste versie op: dan krijg je altijd de laatste vaste versie met de juiste controlegetallen.

**Netwerk:** de pipeline moet `raw.githubusercontent.com` (scanscript), `checkmijn-ai.github.io` (scanner van de dag) en `pypi.org` / `files.pythonhosted.org` (het pakket voor de handtekening) kunnen bereiken. GitLab en Bitbucket installeren daarnaast `git` uit de Debian-pakketbron.
