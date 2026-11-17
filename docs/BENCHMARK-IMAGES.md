# Images Docker/OCI : comparatifs et parcours — 5 novembre 2026

**Actualisation du 6 novembre :** la passe Freexian ELTS porte le comparatif NGINX
à 634 tuples CVE communs sur 788 avec Trivy et à 598 sur 600 avec Grype. Les 154
écarts bruts Trivy comprennent 77 évaluations non affectées et 77 indéterminées.
Les chiffres et limites de cette passe figurent dans la dernière section ; les
mesures précédentes restent datées de leur propre étape.

Les parcours direct, flotte et transfert hors ligne produisent les mêmes
observations sur les deux images testées. Cela ne signifie pas que leur couverture
des vulnérabilités est exhaustive : le comparatif révèle un écart important sur
NGINX/Debian 11 et une limite d'identification du programme principal de Traefik.

Les images sont uniquement téléchargées et lues, jamais exécutées. Trivy et Grype
sont des comparateurs externes ; VV ne les appelle pas. Ces résultats concernent
le workspace de développement 1.2.1, pas une version publiée ou un serveur déployé.

Les préfixes de répertoire personnel de deux fichiers de provenance publiés sont
remplacés par `<home>` ; les versions, résultats et empreintes des données
analysées restent ceux des exécutions enregistrées.

## Entrées et méthode

| Projet | Image et plateforme | Digest du manifeste effectivement analysé |
| --- | --- | --- |
| Traefik | `traefik:v2.11.0`, Linux amd64, Alpine 3.19.1 | `sha256:903f89ddacc3059657565d3e5b3b8e8dcba4cc3b8af08183dad6fdc415459111` |
| NGINX | `nginx:1.24.0`, Linux amd64, Debian 11 | `sha256:2e26275ed7a47e8e93f264d39a09ca4bc3f4058c904c75087e237f4ea883f2a1` |

Traefik exerce les modules Go embarqués et APK ; NGINX exerce dpkg, les binaires
ELF, les paquets du fournisseur et un JAR livré dans l'image. Ces anciennes images
mettent à l'épreuve la couverture historique. Elles ne sont pas des recommandations
de déploiement. Debian 11 a terminé son support LTS le 31 août 2026, avant ce test.
[Annonce Debian](https://www.debian.org/releases/bullseye/).

Les trois outils consomment exactement les mêmes layouts OCI. Trivy 0.76.1 et
Grype 0.121.0 utilisent leurs bases rafraîchies le 5 novembre, puis figées pour les
deux scans. Toutes les gravités et les avis sans correctif sont conservés. VV
utilise OSV avec KEV et EPSS ; NVD n'est pas activé dans son profil d'enrichissement.
Grype conserve ses comportements par défaut, dont certains rapprochements CPE.

La comparaison porte sur **type de paquet + nom + version + identifiant déclaré**.
Les relations `aliases`, `upstream` et `relatedVulnerabilities` ne sont utilisées
que lorsqu'elles figurent dans les rapports. Un DLA qui cite plusieurs CVE n'est
pas assimilé à une seule CVE. Les préfixes Go `v`/`go` sont normalisés ; la casse
des noms est conservée et les versions Debian gardent epoch et révision.
Les comptes ne prouvent ni l'exploitabilité ni l'absence de faux positifs.

## Comparatif 1 : Traefik

| Mesure | VigieVuln | Trivy | Grype |
| --- | ---: | ---: | ---: |
| Entrées brutes de vulnérabilité | 214 | 207 | 208 |
| Tuples distincts paquet/version/CVE explicitement liés | 209 | 204 | 206 |
| Tuples CVE communs avec VV | — | 204 | 155 |
| Tuples CVE du comparateur absents de VV | — | 0 | 51 |

VV inventorie 17 paquets OS, 290 composants Go et 20 fichiers binaires, soit 327
composants. Le comptage des binaires ne doit pas être comparé à celui des seuls
paquets : plusieurs fichiers appartiennent au même paquet OS.

Les **207 observations de Trivy sont retrouvées** par identité de paquet/version
et lien explicite d'avis. Les cinq observations supplémentaires de VV suivent les
fiches Go retournées par OSV. Certaines fiches GHSA associées présentent des
intervalles ou noms de modules différents : leur présence dans VV n'est donc pas
présentée comme un gain confirmé de détection.

Sur les 51 différences avec Grype, 47 concernent `traefik@2.11.0` identifié comme
programme générique par signature binaire, puis rapproché de NVD/CPE. VV lit le
module Go principal, mais sa version embarquée vaut `(devel)` et il ne lui attribue
pas automatiquement la version des labels OCI. La documentation de l'éditeur
confirme au moins un candidat de vulnérabilité pour cette version ; la configuration
requise et les 46 autres observations n'ont pas été validées individuellement.
Les quatre autres différences sont des rapprochements NVD/CPE sur BusyBox et zlib,
absents du snapshot Alpine OSV utilisé. Un rapprochement upstream ne suffit pas à
conclure sur les correctifs d'une distribution.

[Comparaison détaillée](benchmark-evidence/2026-11-05-images/traefik-comparison.json)
· [Revue des écarts et sources primaires](benchmark-evidence/2026-11-05-images/traefik-adjudication.md)
· [Rapport VV](samples/traefik-image.html).

## Comparatif 2 : NGINX

| Mesure | VigieVuln | Trivy | Grype |
| --- | ---: | ---: | ---: |
| Entrées brutes de vulnérabilité | 80 | 806 | 600 |
| Tuples distincts paquet/version/CVE explicitement liés | 155 | 788 | 600 |
| Tuples CVE communs avec VV | — | 153 | 153 |
| Tuples CVE du comparateur absents de VV | — | 635 | 447 |

**L'écart est important et n'est pas résolu.** Les trois inventaires contiennent
les mêmes 142 paquets Debian avec leurs versions. VV recense également 765 fichiers
binaires. Grype ajoute une identité Maven pour `libintl`; VV la conserve comme
archive dont la coordonnée est insuffisamment établie.

L'audit des 643 observations Trivy et 447 observations Grype non rapprochées de VV
montre qu'aucune n'a de fiche correspondante dans le snapshot OSV `Debian:11`
sélectionné, avec les mêmes paquets sources et identifiants. Ce résultat distingue
un déficit des données utilisées d'un défaut de comparaison des versions.
Le JSON actuel du Debian Security Tracker ne contient pas non plus de portée
`bullseye` pour ces observations ; il ne permet donc pas d'arbitrer rétrospectivement
tous les résultats des bases des comparateurs.

Cela **ne prouve pas que les alertes des comparateurs sont fausses**, ni que l'image
est saine. Le chargement complet d'une archive OSV ne garantit pas la conservation
de toutes les données historiques d'une distribution. Un support complémentaire
des données historiques/fournisseur et de leur couverture reste nécessaire pour
réduire cet écart. Les paquets provenant du fournisseur NGINX exigent aussi de
conserver leur provenance, plutôt que de supposer qu'un avis Debian les décrit
exactement.

[Comparaison détaillée](benchmark-evidence/2026-11-05-images/nginx-comparison.json)
· [Audit de chaque différence](benchmark-evidence/2026-11-05-images/nginx-source-audit.json)
· [Fiches primaires conservées](benchmark-evidence/2026-11-05-images/nginx-primary-records.json)
· [Rapport VV](samples/nginx-image.html).

## Validation des parcours lors de la première passe du 5 novembre

| Parcours | Résultat réellement vérifié |
| --- | --- |
| Direct, sans Docker ni commandes externes | Deux scans des layouts OCI ; `PATH=/nonexistent` et appels de subprocess interdits |
| Air gap après export/import | Cache importé dans un autre répertoire ; identités, avis, gravités, KEV et EPSS identiques ; zéro tentative réseau |
| Flotte / `serve-cache` | Deux images via proxy local uniquement ; mêmes tuples que le direct ; reprise offline identique |
| `cache prepare` depuis l'inventaire | Préparation Traefik, transfert vers un cache de client distinct, 214 constats retrouvés hors ligne |
| Serveur public local | Véritable service, SQLite et tokens ; requêtes OSV distro ciblées, deux avis Debian retrouvés et rejoués hors ligne |
| Serveur principal local | Même preuve avec le service principal ; le refus des archives bulk reste actif |
| Serveur hébergé en production | **Non validé et non déployé** ; nécessite la dépendance CLI mise à jour |

Les essais des serveurs utilisent des réponses OSV réelles figées sur un paquet
Debian, avec la bibliothèque CLI du workspace injectée dans les deux services
locaux. Ce sont des preuves du raccordement des services, pas deux scans complets
exécutés sur le serveur public en production.

Les corrections apportées pendant cet audit sont : reprise de la configuration
réseau par `image`, isolation du cache par origine de proxy, transport des avis OS
via les fournisseurs, consultations ciblées compatibles avec le serveur hébergé,
préparation depuis un inventaire et import/export cohérent avec `--cache-dir`.
L'acquisition explicite d'une image OCI reste un accès au registre ; le proxy des
sources de vulnérabilités n'est pas un miroir d'images privées.

Un cache partiel peut être transféré avec ses informations de couverture. Le filtre explicite
`--fail-on-incomplete` permet d'échouer sans transformer les données inconnues en
verdicts propres. Les limites intrinsèques d'identification restent dans le contexte
du scan ; les alertes décrivent les échecs de consultation ou de lecture documentés.

[Preuve direct/air gap et commandes](benchmark-evidence/2026-11-05-images/vv-pathways.json)
· [Flotte et transfert](benchmark-evidence/2026-11-05-images/fleet-proxy-smoke.md)
· [Preuve des deux services](benchmark-evidence/2026-11-05-images/server-osv-e2e.json).

## Reproduction

Les [versions, digests et empreintes](benchmark-evidence/2026-11-05-images/provenance.json)
et les scripts sont conservés dans le dossier de preuves. Les layouts et les bases
volumineuses restent dans `/tmp/vv-image-benchmark-20261105` sur le poste de test.
Les résultats bruts compressés sont conservés dans `raw/` avec leur manifeste.

```bash
bash docs/benchmark-evidence/2026-11-05-images/run-comparators.sh
node docs/benchmark-evidence/2026-11-05-images/scripts/run-vv.cjs
node docs/benchmark-evidence/2026-11-05-images/scripts/compare.cjs \
  /tmp/vv-image-benchmark-20261105 \
  docs/benchmark-evidence/2026-11-05-images vv-final
node docs/benchmark-evidence/2026-11-05-images/scripts/server-osv-e2e.js
```

Les comparateurs nécessitent leurs propres exécutables et bases uniquement pour
reproduire le benchmark. Les scans VV n'en dépendent pas. Une actualisation future
des sources peut modifier les résultats ; les hashes documentent les scans présents.

La validation initiale comprenait une compilation Linux Bun, puis un scan offline
avec `PATH=/nonexistent`.

## Rapports, deltas et déploiement du 5 novembre

Les exemples publiés présentent le résumé de chaque image dans un tableau léger,
également repris au début de sa sous-section CVE. L'inventaire et les corrections
forment un seul tableau, replié par défaut dans le HTML. Les lignes de correction
restent disponibles lorsqu'un ancien export contient un inventaire incomplet.

Les détails EUVD sont désormais disponibles pour les 103 CVE liées à NGINX et les
176 liées à Traefik. Huit réponses ENISA valides dépassaient l'ancien budget de
4 Mio : le lecteur utilise maintenant un budget configurable de 32 Mio. Les
nouveaux exemples ne présentent aucune alerte ; cela ne transforme pas les
limites d'identification ou de couverture en preuve d'exhaustivité.

Le [rejeu des deltas](benchmark-evidence/2026-11-05-images/delta-metadata-replay.json)
compare les exports précédant cette actualisation de métadonnées aux exports des
HTML publiés : 80 constats inchangés pour NGINX, 212 pour Traefik, aucun ajout ni
retrait. Les tests couvrent séparément les changements d'alias, les avis multi-CVE,
les occurrences par image, les changements de digest liés à une déclaration et
les interruptions de sources. Une nouveauté ou une disparition non démontrable
reste indéterminée dans les exports, le rapport et la console.

Validation : **2 163 tests CLI réussis, 11 ignorés, aucun échec** ; **583 tests
serveur réussis** ; **91 tests des opérations de déploiement réussis**. Après le
dernier ajout des compteurs indéterminés dans la console, les 25 tests ciblés de
delta et de remédiation passent également. Les quatre sommes de contrôle des
exemples et `git diff --check` sont valides.

Le serveur public a été mis à jour avec le même paquet CLI, incluant ses nouvelles
dépendances d'archives. Web, worker et curation utilisent l'image immuable consignée
dans le [reçu de déploiement](benchmark-evidence/2026-11-05-images/deployment-20261105.json).
Le verrou de déploiement a été vérifié ; PostgreSQL et le WAF n'ont pas été recréés.
L'import Debian a intégré 73 526 avis. Les contrôles HTTP de santé et des pages
`DLA-4485-1` et `DLA-3951-1` répondent 200 ; cette dernière relie bien
`CVE-2024-8096`. Ces contrôles de production ne remplacent pas les preuves de scans
directs, flotte et hors ligne décrites plus haut. Aucun commit n'a été créé.

## Réduction des écarts de détection — 5 novembre 2026

Cette seconde passe utilise les mêmes digests d'image et les sorties Trivy/Grype
figées du premier comparatif. Les nouveaux inventaires et les sources ajoutées
sont rejoués sur une copie des caches. Les comptes des sections précédentes
restent ceux de leur étape ; les exemples HTML actuels correspondent à cette passe.

| Mesure | Avant | Après |
| --- | ---: | ---: |
| Traefik : constats bruts VV | 212 | 267 |
| Traefik : observations Trivy retrouvées, coordonnées exactes | 207 / 207 | 207 / 207 |
| Traefik : observations Grype retrouvées, coordonnées exactes | 157 / 208 | 157 / 208 |
| Traefik : recoupements supplémentaires sur le même binaire identifié | — | 38 / 47 |
| NGINX : constats bruts VV | 80 | 320 |
| NGINX : tuples paquet/version/CVE Trivy encore absents | 635 | 559 |
| NGINX : tuples paquet/version/CVE Grype encore absents | 447 | 367 |

Le rapprochement du programme Traefik est présenté **séparément** : Grype utilise
une coordonnée de binaire générique, VV un module Go. La relation repose sur le
même digest d'image, le chemin et la version, avec une preuve d'identité VCS/proxy ;
elle ne modifie pas silencieusement le comparatif exact. Neuf observations sur le
programme et quatre observations de distribution restent non résolues.
Voir [la preuve Go et la comparaison](benchmark-evidence/2026-11-05-images/recall/traefik-go-main.md).

NGINX ajoute 217 constats issus de l'historique Debian et 23 issus du fournisseur.
Les constats de sources différentes peuvent désigner les mêmes couples paquet/CVE :
le rapport les rassemble en **254 lignes**, portant **176 CVE distinctes**. Le
rapport Traefik affiche **267 lignes**, portant **223 CVE distinctes**. Les nouvelles
versions ne sont pas déduites du numéro de version de l'image seule.

L'[audit détaillé des écarts NGINX](benchmark-evidence/2026-11-05-images/recall/nginx-gap-audit.md)
classe les 559 tuples Trivy encore absents : 231 sans preuve bullseye explicite,
194 absents du snapshot CVE historique et 134 avec un statut sans borne de version.
Pour Grype, les 367 tuples se répartissent en 232 sans preuve bullseye explicite
et 135 sans borne de version. Ces catégories ne démontrent pas des faux positifs.
Les versions sans borne restent des observations, consultables dans le rapport.

Les deux rapports finaux sont rejoués hors ligne avec leurs métadonnées préparées,
sans avertissement. Le rejeu NGINX emploie l'exécutable compilé avec
`PATH=/nonexistent`. Les identités, gravités, scores et versions correctives restent
identiques au dernier résultat connecté pour NGINX et au rejeu préparé pour Traefik.
Cela ne signifie pas que les snapshots couvrent toutes les vulnérabilités :
l'historique Debian s'arrête au commit sélectionné et les candidats Alpine n'ont
pas tous une applicabilité démontrable. Les tests de transport indépendants couvrent
les services de flotte et hébergé locaux, ainsi que l'export/import du cache.

[Comparaisons exactes finales](benchmark-evidence/2026-11-05-images/recall/final-comparison/)
· [Rejeu et couverture](benchmark-evidence/2026-11-05-images/recall/final-replay.json)
· [Architecture et plan réalisés](PLAN-native-images-linux.md#extension-de-couverture-après-comparaison--5-novembre-2026).

Validation finale de cette passe : **2 236 tests CLI réussis, 11 ignorés**, et
**585 tests serveur réussis**. Un rejeu séparé des deux images avec interception de
`fetch`, HTTP, HTTPS et des connexions réseau a observé **zéro tentative réseau**
et les mêmes constats canoniques que les rapports publiés. Le navigateur Chromium
confirme l'absence de débordement horizontal dans la vue vérifiée, les tableaux de
compteurs et les encarts de provenance. Les dates numériques des consultations
sont aussi rendues avec `<time>`. Les [preuves de validation](benchmark-evidence/2026-11-05-images/recall/validation.json)
séparent tests unitaires/intégration, compilateur et contrôle visuel.

Le serveur a été mis à jour avec cette bibliothèque CLI. Le [reçu et les notes
de déploiement](benchmark-evidence/2026-11-05-images/recall/deployment-notes.md)
consignent l'image de web/worker/curation, les contrôles HTTP 200 et la correction
des permissions de l'archive de construction après un premier retour automatique.
Le verrou est vérifié ; PostgreSQL et le WAF restent les mêmes conteneurs.

## Troisième passe : réduction des écarts — replays finaux

Cette passe reprend les mêmes manifests et sorties Trivy/Grype figées. Elle ajoute
la prise en compte des annotations Debian historiques, des avis officiels NGINX,
des annonces publiques Extended LTS de Freexian et des enregistrements CVEProject
pour le module Go principal. Les chiffres suivants décrivent les replays finaux ; ils ne remplacent pas
les baselines précédentes.

| Mesure | Traefik | NGINX |
| --- | ---: | ---: |
| Constats bruts VV | 285 | 707 |
| CVE distinctes explicitement liées dans VV | 234 | 409 |
| Tuples paquet/version/CVE VV | 273 | 629 |
| Tuples Trivy absents de VV, comparaison exacte | 0 / 204 | 185 / 788 |
| Tuples Grype absents de VV, comparaison exacte | 51 / 206 | 2 / 600 |

Pour Traefik, la comparaison exacte garde séparées l'identité générique de Grype
et celle du module Go. Une comparaison additionnelle est possible pour le même
exécutable grâce au digest de l'image et au chemin du binaire, à son hash, à sa
révision VCS et à la correspondance entre l'origine du module Go et le tag. Elle
recoupe 46 des 47 observations Grype sur ce programme : après ce rapprochement
**conditionnel**, cinq observations Grype restent non rapprochées. L'une concerne
une CVE dont la source primaire vise la branche majeure 3 ; quatre concernent
BusyBox ou zlib et restent des candidats Alpine indéterminés. Le tracker Alpine
qualifie précisément zlib de « possibly vulnerable », sans établir l'applicabilité
exacte de la version BusyBox inventoriée. L'identité du binaire ne prouve pas que
les fonctions vulnérables sont atteignables.

Pour NGINX, les deux tuples Grype restants portent sur le paquet NGINX du
fournisseur, auquel Grype associe des données Debian. Le mainteneur NGINX indique
que [CVE-2013-0337 ne s'applique pas aux paquets nginx.org](https://trac.nginx.org/nginx/ticket/2361) ;
pour [CVE-2023-44487](https://mailman.nginx.org/pipermail/nginx/2023-October/BZBAIL3BGCJWZGOPZH4LO4DQWZ25EBA5.html),
il décrit une protection dans la configuration par défaut et des mitigations
supplémentaires. Ces déclarations ne prouvent pas toutes les configurations du
conteneur. Les 185 tuples Trivy restants ne sont pas qualifiés globalement de faux
positifs : ils restent à examiner avec leur source, leur version et leur portée.
Les annonces ELA identifient des correctifs pour des versions Debian précises ;
elles ne déclarent pas nécessairement la borne d'introduction et leur installation
nécessite l'accès au dépôt Extended LTS correspondant.

Les [comparaisons et preuves de cette passe](benchmark-evidence/2026-11-05-images/reduction/README.md)
conservent les sorties exactes et la comparaison du binaire séparée. Les sources
n'ont pas toutes une couverture complète ; ces comptes ne démontrent ni
l'exploitabilité des constats ni l'absence d'autres vulnérabilités.

## Mise à jour Freexian ELTS — 6 novembre 2026

La dernière passe réutilise les mêmes images et inventaires figés. Elle ajoute le
tracker Freexian et ses preuves ciblées par CVE, paquet source, version installée
et distribution ; le rejeu ne transforme pas une borne d'une autre release en
verdict Bullseye. Les [résultats et preuves figés](benchmark-evidence/2026-11-06-images/elts/README.md)
comprennent les comparaisons recalculées, les exports JSON compressés, les empreintes
et les évaluations individuelles.

| Image | Findings VV | Tuples CVE Trivy communs / total | Tuples CVE Grype communs / total |
| --- | ---: | ---: | ---: |
| NGINX Debian 11 | 739 | 634 / 788 | 598 / 600 |
| Traefik Alpine | 285 | 204 / 204 | 155 / 206 |

Pour NGINX, les 185 tuples Trivy auparavant résiduels se répartissent désormais
entre **31 confirmés**, **77 non affectés** selon les preuves Bullseye et **77
indéterminés**. La différence brute reste de **154 tuples**, soit 77 non affectés
et 77 indéterminés : elle ne doit pas être présentée comme 77 écarts bruts. Les
175 observations complémentaires du rapport sont distinctes des 739 findings.
Pour Traefik, 46 des 51 tuples Grype non identiques sont reliés au même binaire ;
cinq restent sans rapprochement établi. Ces relations ne sont pas des égalités de
tuples et ne modifient pas le compte exact de 155 / 206.

Les deux rapports ont été rejoués hors ligne avec zéro tentative réseau. Le
rapport NGINX conserve un avertissement historique : 28 fiches EUVD ont répondu
HTTP 403 ; celui de Traefik en conserve un pour 11 fiches. Le jeu NGINX a aussi été
rejoué avec l'exécutable autonome. La suite CLI après le correctif mémoire compte 2 337 réussites,
11 tests ignorés et zéro échec ; la suite serveur compte 599 réussites. Les sections
précédentes décrivent leurs propres passes historiques et ne sont pas les comptes
finaux. Ces résultats ne prouvent pas une couverture complète.


La livraison du 6 novembre est [déployée et vérifiée](benchmark-evidence/2026-11-06-images/elts/deployment.json) : web, worker et curation utilisent la nouvelle CLI. Le dump complet Freexian reste côté serveur ; les clients reçoivent les paquets demandés. Les contrôles réels du relais et les réponses HTTP 200 des points de santé sont archivés dans le dossier de preuves. Le rejeu autonome final conserve les références registre vérifiées et les mêmes résultats que Node. Les 77 cas NGINX encore indéterminés restent ouverts ; cette livraison n'annonce pas une parité exhaustive avec Trivy ou Grype.
