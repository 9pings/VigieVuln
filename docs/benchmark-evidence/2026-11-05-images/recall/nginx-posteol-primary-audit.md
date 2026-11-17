# NGINX / Debian 11 — examen primaire des écarts post-LTS

Cet examen porte sur les 194 tuples Trivy absents du snapshot Debian historique
arrêté au 31 août 2026. Les neuf couples paquet/CVE déjà reliés aux avis Freexian
pour bullseye sont analysés séparément ; restent ici **185 tuples, correspondant
à 98 CVE**. Il s'agit d'un audit du benchmark, pas d'une règle de détection
ajoutée au scanner. Les résultats bruts des comparateurs sont conservés.

| Déclaration CNA comparée à l'identité/version source inventoriée | Tuples | CVE distinctes |
| --- | ---: | ---: |
| Version upstream hors des plages examinées, sous réserve des modifications Debian | 46 | 21 |
| Version upstream dans une plage affectée, sous réserve des correctifs Debian et conditions d'exécution | 55 | 29 |
| Identité, plage ou ordre de version insuffisant pour conclure | 84 | 48 |
| **Total** | **185** | **98** |

Il n'y a, parmi ces 185 tuples, aucun verdict direct sur un paquet Debian exact
qui soit établi par cette comparaison CNA. Un résultat « upstream non affecté »
n'est donc pas présenté comme une preuve absolue d'absence dans le paquet Debian :
un rétroportage peut introduire du code. Inversement, un résultat upstream affecté
ne prouve pas que le paquet Debian reste vulnérable après ses correctifs. La
présence du paquet source ne prouve pas non plus que chacun de ses paquets binaires
expose le code concerné. Aucune condition d'exploitation à l'exécution n'a été
testée.

Le tracker Debian courant contient, parmi les 185 tuples, **69 annotations
`bookworm <not-affected>`** pour le même paquet source. Dans ce groupe, 38 tuples
ont aussi une version upstream qui ne tombe pas dans les plages CNA examinées ;
31 restent indéterminés. L'annotation d'une release voisine ne tranche pas à elle
seule l'état de bullseye. Les CVE peuvent également avoir été ajoutées au tracker
après le snapshot historique ; l'absence du snapshot ne détermine ni leur date de
publication ni l'applicabilité du code dans l'image.

Exemples de preuves à examiner dans leur contexte :

- [`CVE-2026-76642`](https://www.cve.org/CVERecord?id=CVE-2026-76642) : la
  fiche CNA indique des plages util-linux commençant à `2.39` et `2.42` ; la
  version source installée a une base upstream `2.36.1`. L'exclusion de la plage
  upstream reste conditionnelle à l'absence d'un rétroportage introduisant le code.
- [`CVE-2026-13608`](https://www.cve.org/CVERecord?id=CVE-2026-13608) : la
  première plage CNA curl commence à `7.82.0`, contre une base installée `7.74.0`.
  La fiche décrit une négociation LDAP/SASL ; l'utilisation effective n'est pas
  établie par l'inventaire.
- [`CVE-2026-18924`](https://www.cve.org/CVERecord?id=CVE-2026-18924) : la
  base upstream curl `7.74.0` se trouve dans une plage CNA affectée. La fiche
  décrit une condition liée à HTTP/2 Server Push et au partage de connexions ; les
  correctifs Debian et la configuration effective restent à vérifier.

Les avis ELA retirés du périmètre ne prouvent pas tous une borne d'introduction :
ils établissent un correctif annoncé pour bullseye. Pour
[`CVE-2026-109518`](https://www.cve.org/CVERecord?id=CVE-2026-109518), la fiche
CNA contient en outre une plage Debian APT explicite incluant `2.2.4` ; son
exploitation dépend notamment de la configuration de nouvelles tentatives et du
scénario de redirection décrits dans la fiche. Ces éléments ne doivent pas être
étendus automatiquement aux autres ELA.

La [donnée machine](nginx-posteol-primary-audit.json) conserve chaque tuple, le
nom du CNA, le texte descriptif et les URL de référence publiés, les plages et
comparaisons, le statut bookworm et le SHA-256 de la fiche utilisée. Le
[script d'audit](audit-posteol-primary.js) est reproductible avec les fiches
CVEProject et le `CVE/list` courant enregistrés localement. Le raccordement d'un
produit CNA au paquet source se limite ici à un nom exact insensible à la casse ;
un produit non identifié reste inconnu. Les CVE et sources non présentes ne sont
pas déduites par analogie. Une seule fiche parmi ces 185 tuples n'était pas
disponible dans le jeu local.

Le schéma CVE distingue `affected`, `unaffected` et `unknown` et exige un
`versionType` pour l'ordre des plages : [spécification CVE des versions](https://github.com/CVEProject/cve-schema/blob/main/schema/docs/versions.md).
Pour les champs CNA `custom` strictement numériques, cet audit utilise une
comparaison des composantes numériques **à titre conditionnel** ; ce n'est pas
une garantie générale de l'ordre d'une version personnalisée. Les versions Git,
les plages non comparables et les preuves contradictoires ne deviennent pas des
verdicts de version. Sources et limites de l'étape précédente :
[audit des écarts historiques](nginx-gap-audit.md).
