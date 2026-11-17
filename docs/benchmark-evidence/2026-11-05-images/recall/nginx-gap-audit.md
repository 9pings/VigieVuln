# NGINX / Debian 11 — audit des écarts restants

Cet audit porte sur le rejeu du 5 novembre 2026 de `nginx:1.24.0`, manifeste
Linux amd64 `sha256:2e26275ed7a47e8e93f264d39a09ca4bc3f4058c904c75087e237f4ea883f2a1`.
Le rapport VigieVuln analysé comprend **320 avis bruts** : 80 OSV, 217 issus du
tracker historique Debian et 23 de la source NGINX. Un avis brut n'est pas un
unique couple paquet/CVE ; les CVE explicitement liées aux avis sont projetées
séparément pour la comparaison. Les résultats de référence n'ont pas été modifiés.

La comparaison déduplique les tuples **type de paquet, nom, version et identifiant
CVE**, avec conservation de l'epoch Debian. Elle trouve 254 tuples CVE distincts
pour VigieVuln, 788 pour Trivy et 600 pour Grype. Les intersections sont
respectivement de 229 et 233 ; restent **559 tuples Trivy** et **367 tuples Grype**
sans tuple correspondant dans VigieVuln. Les deux colonnes partagent **364 tuples** :
leurs chiffres ne s'additionnent pas. À titre de comparaison, l'audit antérieur indiquait
635 et 447 tuples absents, sur les mêmes entrées de comparateurs ; les changements
de couverture et de représentation sont détaillés dans les exports machine.

| Preuve disponible pour les tuples absents | Trivy | Grype |
| --- | ---: | ---: |
| CVE et paquet source présents dans le `CVE/list` historique, sans statut ni correctif bullseye explicite dans les trois listes consultées | 231 | 232 |
| CVE absente du `CVE/list` au commit historique | 194 | 0 |
| Statut bullseye explicite sans borne de version exploitable | 134 | 135 |
| **Total** | **559** | **367** |

Les statuts non bornés sont, pour Trivy, 11 `no-dsa`, 89 `postponed` et
34 `ignored` ; pour Grype, 11, 90 et 34 respectivement. Par exemple,
`bash` / `CVE-2022-3715` porte un statut `no-dsa` bullseye, et
`util-linux` / `CVE-2026-27456` un statut `postponed`. Ces statuts donnent une
information de triage, sans prouver à eux seuls que toute version installée est
affectée. À l'inverse, leur présence ne prouve pas non plus que le comparateur a
produit un faux positif. Les analyses conditionnelles restent à examiner avec
les bornes d'introduction et le contexte de chaque paquet.

L'absence d'une CVE dans le snapshot historique ne prouve ni sa date de publication
ni son inapplicabilité : elle peut notamment avoir été ajoutée plus tard, ne pas
avoir été suivie dans ce fichier ou relever d'une autre source. Debian 11 a terminé
son support LTS le 31 août 2026 ; l'historique s'arrête à ce jalon et ne couvre donc
pas à lui seul les vulnérabilités découvertes ensuite. La donnée générale `sid`
ne suffit pas à déduire qu'une version bullseye est affectée, notamment à cause
des rétroportages. [Documentation du tracker Debian](https://security-team.debian.org/security_tracker.html)
· [Annonce de fin de support](https://www.debian.org/News/2026/20260831).

Les tuples sont reliés au nom et à la version du paquet **binaire** dans
l'inventaire, puis au nom et à la version de son paquet **source** pour examiner
les informations Debian. Les noms/versions installés ne constituent pas une
preuve cryptographique d'origine. Dans cette image, `nginx` est empaqueté par
NGINX/F5 ; sa source fournisseur est évaluée séparément, sans attribuer
systématiquement ses bornes upstream aux paquets Debian. La version source des
paquets binaires peut différer de leur version binaire, y compris pour les epochs
ou reconstructions ; l'audit ne les substitue pas.

Parmi les tuples Grype restants, deux concernent le paquet fournisseur `nginx` :
`CVE-2013-0337` possède une annotation historique Debian `ignored`, et
`CVE-2023-44487` n'a pas de preuve bullseye explicite dans le snapshot étudié.
Ces deux éléments appellent une vérification fournisseur distincte ; la présence
ou l'absence d'une annotation Debian ne tranche pas leur applicabilité au paquet F5.

Le détail par tuple, les catégories et les empreintes exactes sont dans
[nginx-gap-audit.json](nginx-gap-audit.json). Le script
[audit-nginx.js](audit-nginx.js) le recalcule à partir des fichiers de comparaison,
d'inventaire et du cache historique complets indiqués en arguments. Il vérifie
l'empreinte de `CVE/list` et le commit avant l'analyse. Snapshot primaire : commit
[`b66660b4eb40ad61cf5d8235defe557f26fde81c`](https://salsa.debian.org/security-tracker-team/security-tracker/-/commit/b66660b4eb40ad61cf5d8235defe557f26fde81c),
`CVE/list`, `DSA/list`, `DLA/list` ; état arrêté au 31 août 2026. Les sources ne
prouvent ni l'exploitabilité à l'exécution ni la justesse individuelle de tous
les résultats des comparateurs.
