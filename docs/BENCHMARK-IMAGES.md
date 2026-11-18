# Comparatif d'images Docker/OCI

Ce comparatif daté du **6 novembre 2026** porte sur deux images publiques. Il
compare l'inventaire et les avis de VigieVuln (VV), Trivy et Grype avec les
sources et configurations indiquées ci-dessous. Les images sont lues sans être
exécutées. Les résultats ne démontrent ni l'exploitabilité ni une couverture
exhaustive et peuvent changer avec les bases de vulnérabilités.

## Entrées et méthode

| Image, plateforme et distribution | Digest du manifeste analysé |
| --- | --- |
| `traefik:v2.11.0`, Linux amd64, Alpine 3.19.1 | `sha256:903f89ddacc3059657565d3e5b3b8e8dcba4cc3b8af08183dad6fdc415459111` |
| `nginx:1.24.0`, Linux amd64, Debian 11 | `sha256:2e26275ed7a47e8e93f264d39a09ca4bc3f4058c904c75087e237f4ea883f2a1` |

Les trois outils analysent les mêmes layouts OCI. Les comparateurs sont Trivy
0.76.1 et Grype 0.121.0, avec leurs bases figées pour ces scans. Les sources de
VV et leurs limites sont précisées dans les preuves. Les trois outils ne sont pas
interchangeables : ils peuvent utiliser des sources et règles d'applicabilité
différentes, notamment pour les correctifs de distribution.

La comparaison exacte porte sur **type de paquet, nom, version et identifiant CVE
explicitement lié**. Une relation `aliases`, `upstream` ou
`relatedVulnerabilities` n'est utilisée que si le rapport la déclare. Un avis DLA
qui cite plusieurs CVE n'est pas assimilé à une seule CVE. Les préfixes Go
`v`/`go` sont normalisés ; les versions Debian conservent epoch et révision.

## Résultats

| Image | Findings VV | Tuples CVE Trivy communs / total Trivy | Tuples CVE Grype communs / total Grype |
| --- | ---: | ---: | ---: |
| Traefik Alpine | 285 | 204 / 204 | 155 / 206 |
| NGINX Debian 11 | 739 | 634 / 788 | 598 / 600 |

Ces comptes décrivent le jeu et les règles de rapprochement ci-dessus, pas un
score général de rappel ni un classement des outils.

### Traefik

Les tuples Trivy du jeu sont tous rapprochés de VV. Pour Grype, les 51 tuples
sans égalité exacte incluent des observations sur le programme principal identifié
comme binaire générique. Une comparaison distincte par digest d'image, chemin,
hash, révision VCS et origine du module relie 46 de ces tuples au même exécutable ;
cette relation conditionnelle ne change pas les 155 égalités exactes. Les autres
observations restent à examiner. L'identité du binaire ne prouve pas que le code
vulnérable est atteint.

[Comparaison et preuves Traefik](benchmark-evidence/2026-11-05-images/reduction/README.md)
· [Rapport d'exemple](samples/traefik-image.html).

### NGINX

Les inventaires contiennent les 142 paquets Debian et leurs versions. Parmi les
154 tuples Trivy sans égalité exacte avec VV, les éléments de preuve retenus en
classent 77 comme non affectés pour Bullseye et 77 comme indéterminés. Ils ne
constituent pas une preuve que toutes les alertes des comparateurs sont fausses ou
que l'image est saine. Deux tuples Grype restent sans égalité exacte et concernent
le paquet NGINX du fournisseur ; la provenance du paquet et les conditions des
avis doivent être vérifiées. Les conclusions liées à un snapshot historique ou à
un fournisseur ne couvrent pas automatiquement d'autres dates ou distributions.

[Résultats et preuves NGINX](benchmark-evidence/2026-11-06-images/elts/README.md)
· [Avis historiques Debian](HISTORICAL-DEBIAN.md)
· [Rapport d'exemple](samples/nginx-image.html).

## Parcours et reproduction

Les parcours directs, proxy de flotte et transfert de cache ont été vérifiés sur
les entrées et données documentées. Les rapports ont aussi été rejoués hors ligne
avec interception réseau. Un rejeu hors ligne dépend de l'inventaire et des sources
préparés ; il ne complète pas les données absentes. Dans ces résultats, des
consultations de détails EUVD ont reçu HTTP 403 et sont signalées dans les rapports.

Les [preuves et métadonnées de comparaison](benchmark-evidence/2026-11-06-images/elts/README.md),
la [provenance des entrées](benchmark-evidence/2026-11-05-images/provenance.json)
et les [scripts de reproduction](benchmark-evidence/2026-11-05-images/) décrivent
les commandes, sorties et empreintes. Les comparateurs exigent leurs propres
exécutables et bases pour être rejoués ; VV n'en dépend pas. Les images et bases
volumineuses doivent être obtenues séparément.

Pour les formats, les sources et les gates pris en charge par le CLI, voir
[IMAGES.md](IMAGES.md). Pour les comparaisons de projets sources, voir
[BENCHMARK.md](BENCHMARK.md).
