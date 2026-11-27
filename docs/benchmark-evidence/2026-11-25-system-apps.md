# Inventaire système sur une boutique PrestaShop déployée

Recette du 25 novembre 2026. La question est de savoir quelles applications un auditeur peut identifier à partir du seul JSON collecté sur un système ou une image. Les comptages ci-dessous portent sur les enregistrements d’inventaire, qui peuvent décrire plusieurs occurrences d’un même composant. Le cache d’avis de sécurité du test était vide.

## Terrain et vérification indépendante

| Cible locale | Vérité terrain | Mesure initiale avant modification |
|---|---|---|
| Image WordPress `wordpress:php8.3-apache` | WordPress 7.1.5 dans `/usr/src/wordpress/wp-includes/version.php`, PHP 8.3.37 et Apache 2.4.71 | PHP et Apache identifiés. Trois descripteurs de projets relevés, dont celui d’un thème. Aucune instance WordPress dans le rapport. |
| Image `mariadb:11.4` | Le serveur indique 11.4.13. | Le paquet `mariadb-server` donne la version de distribution `1:11.4.13+maria~ubu2404`. Le binaire `mariadbd` est également inventorié, sans version propre. |
| Image `prestashop/prestashop:9.0.0` | Deux copies de `src/Core/Version.php` portent la version 9.0.0, sous `/tmp/data-ps/prestashop` et `/var/www/html`. Leur empreinte est identique. | 134 chemins de descripteurs. PHP 8.4.28 et Apache 2.4.71 sont identifiés. L’inventaire ne dit pas quelle copie sert la boutique. |
| Fichiers de la boutique PrestaShop installée, sous `/var/www/html` | La page d’accueil répond en HTTP 200 et contient le produit « Hummingbird printed t-shirt ». MariaDB confirme 19 produits actifs, 76 modules actifs et la version de schéma 9.0.0. | 67 chemins de descripteurs, 9 409 enregistrements et zéro entrée dans `applications`. En analyse hors ligne avec cache vide, le détail filtré de `findings.json` expose 2 904 composants. |
| Image `ghost:5-alpine` | Le manifeste racine du CMS Node déclare Ghost 5.130.6. | L’identité et la version du projet sont retrouvées. Sous `node_modules`, 2 439 enregistrements sont transitifs et 14 sont directs. Les exceptions comprennent des exécutables livrés avec les paquets. |

La boutique utilise les données de démonstration de la distribution publique. Apache a été lancé sur l’arbre installé après une erreur de renommage de l’administration en fin d’installation. Le test HTTP et la lecture de la base ont été effectués sur le banc local, sans port publié. Ils établissent la vérité terrain et ne sont pas des opérations de la collecte. Les tests sur les images ont utilisé des archives `docker image save`. La collecte de l’arbre installé a porté sur une copie des fichiers de la boutique, distincte des images et de la base. [Installation Docker officielle de PrestaShop](https://devdocs.prestashop-project.org/9/basics/installation/environments/docker/)

Empreintes Docker relevées, utiles pour retrouver les entrées de la recette :

- PrestaShop, digest du registre `sha256:c21b89e662b489f6265f9def26dd5986270df34ac7d6c1eb990b2b592135b1ca`.
- WordPress, ID local `sha256:9b46af6a41fd0dcb2e5cf85033a6350d05010356847ede1cfcac5cf94292eb26`.
- MariaDB, ID local `sha256:a8992b5e5404d11e03c54a31d0c1bdea3fd116d283aa6d1a627551f29045309b`.
- Ghost, ID local `sha256:a0506f3f05f5bdc6c950c5113cdcdb1e1f96fbf15f6dc0a39fc093c25348bdb5`.

## Ce que le modèle doit distinguer

1. **Instance et racine.** L’image peut contenir un gabarit d’installation et un document root avec les mêmes fichiers. Conserver les deux chemins et la preuve de version. Relier une racine à un service à partir d’une configuration de document root ou de montage. Le statut d’exécution reste inconnu avec les seuls fichiers de l’image.
2. **Application, thème et module.** Le projet du thème WordPress et le lockfile d’un module PrestaShop doivent rester attribuables à leur sous-racine. Les contrôles actuels du détecteur PrestaShop de scan source manquent aussi cette distribution 9.0.0. Elle contient `config/config.inc.php`, `classes/Tools.php` et la constante littérale de la classe `PrestaShop\PrestaShop\Core\Version`, mais ni `composer.json` à la racine ni `config/settings.inc.php`. Ces marqueurs peuvent être lus statiquement sans ouvrir les paramètres de connexion.
3. **Installation et relation.** Une occurrence dans `node_modules` ou `vendor` doit rester dans l’inventaire avec sa version et son chemin. Son emplacement décrit une dépendance installée. Le manifeste ou le graphe du projet permet ensuite de préciser une relation directe ou transitive. Par exemple, les deux `hiddeninput.exe` sous des répertoires `vendor` de la boutique sont actuellement classés directs.
4. **Bibliothèque partagée et consommateur.** Dans l’image WordPress, 928 enregistrements dont le chemin se termine par `.so` ou `.so.N…` sont classés directs. Dans MariaDB, il y en a 524. Une bibliothèque devrait figurer parmi les dépendances techniques du système. Une relation avec un exécutable précis demande une preuve supplémentaire, par exemple une dépendance ELF `DT_NEEDED` résolue au bon `SONAME` et à la bonne architecture. Les cas ambigus restent sans attribution.
5. **Rapport et périmètre.** Conserver l’ensemble des occurrences et des avis applicables dans les données d’audit. Présenter d’abord les instances et les services, puis leurs dépendances, avec accès aux chemins et aux incertitudes. Une déclaration Compose reste une référence de projet. Une correspondance de tag ne prouve pas le déploiement du contenu inventorié.

Le premier test d’acceptation proposé est la reconnaissance de la boutique 9.0.0 sous sa racine, avec ses modules et ses preuves de version, tout en gardant visible la copie de préparation de l’image. Un second test est le maintien des composants imbriqués de Ghost et des bibliothèques de MariaDB dans les dépendances avec leurs chemins. La collecte doit fournir toutes ces preuves hors ligne pour que l’auditeur puisse les relire sur une autre machine.

## Faisabilité d’un parcours système autonome

Le moteur projet actuel a été exécuté hors ligne sur une arborescence de test réunissant deux installations WordPress 6.6.2 et une application Symfony. Il a retourné trois racines distinctes, `srv/www/blog`, `srv/www/support` et `opt/api`. La collecte système doit conserver ces identités par cible et chemin pour permettre la restitution après transfert du JSON. Les empreintes PHP, Apache et MariaDB gardent leur preuve de version. Les descripteurs sous un CMS, tels ceux des thèmes et modules, se rattachent à l’instance par leur chemin. Le chapitre « Dépendances du système » regroupe les autres composants, avec les chemins, versions et CVE. Si le manifeste établit une relation directe au projet pour un paquet présent dans `node_modules`, les deux informations restent valides.

L’option `--images` du scan projet constitue le modèle pour l’extension du parcours système. Seules les images déclarées par les projets entrent dans cette sélection. Leur contenu reste une cible distincte, liée à la déclaration par son chemin et, si disponible, son digest. Sur un client hors ligne, une référence sans contenu disponible localement doit rester visible comme non inspectée. L’inventaire complet du cache Docker demandé avec `--docker` a une portée plus large.

### Lecture de disques sans programme auxiliaire sur la cible

Un prototype indépendant du CLI distribué a embarqué le lecteur 7-Zip WebAssembly et ses octets WASM dans un seul exécutable Bun 1.4.5. La recette a tourné dans Debian bookworm-slim, sous l’UID 65534, avec le réseau désactivé, la racine et les disques en lecture seule. Aucun Node, 7-Zip, QEMU ni guestmount installé dans ce conteneur. La préparation des disques et la compilation du prototype ont été effectuées sur le poste de développement.

- **Formats effectivement lus** : RAW, QCOW2, VMDK, VHD, VHDX et VDI, chacun avec le même système de fichiers ext4 de 64 Mio. Un essai supplémentaire a utilisé un VHDX avec une table GPT et une partition ext4.
- **Preuves récupérées** : `var/www/front/package-lock.json` (lodash 4.17.21) et `var/www/blog/wp-includes/version.php` (WordPress 6.6.2). Le lecteur a extrait ces deux fichiers en mémoire sans convertir l’image entière et sans la monter sur l’hôte.
- **Taille mesurée** : 110 987 440 octets pour le prototype compilé contre 109 209 776 pour un programme témoin compilé avec le même runtime, soit 1 777 664 octets supplémentaires, environ 1,70 Mio.
- **Limites de la recette** : les chemins étaient connus, la lecture était ciblée et les images étaient de petite taille. La découverte complète, les budgets mémoire et temps sur des volumes réels, les partitions multiples, LVM, les disques chiffrés et les chaînes de snapshots nécessitent leurs propres essais. Le prototype utilisait le port WASM 1.2.0 pour mesurer la faisabilité technique. Le choix d’une version maintenue du décodeur et sa mise à jour font partie de l’intégration de distribution.

La commande de production peut garder `collect` puis `analyse` pour une racine, une archive locale ou un disque. Les essais suivants portent sur le CLI intégré. La liste des formats du moteur de lecture figure dans la [documentation de 7-Zip](https://www.7-zip.org/).


## Recette du parcours intégré

- L’archive de la distribution PrestaShop 9.0.0 contient le site sous `/var/www/html` et son gabarit d’installation sous `/tmp/data-ps/prestashop`. Le script d’initialisation de cette image établit la copie du gabarit vers le site. Le JSON conserve la preuve `src/Core/Version.php` de chaque copie. Le rapport hors ligne retrouve PHP 8.4.28, Apache 2.4.71 et les modules par occurrence. Le chapitre « Dépendances du système » contient les composants techniques avec leurs chemins.
- Sur l’image Ghost 5.130.6, le projet est identifié sous `var/lib/ghost/versions/5.130.6`. Les 2 453 composants sous `node_modules`, exécutables inclus, ont le rôle transitif.
- Une déclaration Compose désignant `wordpress:php8.3-apache` et `mariadb:11.4` produit trois cibles, le répertoire du projet et les deux images du cache Docker. Chaque déclaration identifie sa cible candidate. La recette a utilisé `TMPDIR` sur un volume disposant d’assez d’espace pour extraire les couches.
- Une recette automatisée supprime l’arborescence cliente entre `collect` et `analyse`. Avec un avis Wordfence synthétique et un avis npm de test, le rapport retrouve la version du cœur WordPress, l’instance concernée, la dépendance npm et son lockfile.
- Les binaires Linux ont collecté un VHDX/ext4 sur Alpine 3.20 et un QCOW2/GPT à deux partitions ext4 sur Debian, dans des conteneurs en lecture seule et sans réseau. L’inventaire conserve WordPress 6.6.2 sur chaque partition. Les tests de l’interface CLI couvrent également RAW, VHD, VDI, VMDK, MBR, une partition illisible et la conservation du JSON précédent en cas d’échec.
- WordPress 7.1.5 a été installé avec Apache et MariaDB 11.4 sur un réseau Docker interne. La page HTTP a retourné le titre de la recette. Le binaire a ensuite inventorié le volume web en lecture seule depuis un conteneur sans réseau et retrouvé la version du cœur. Le mot de passe sentinelle de cette installation est absent du JSON.

## CVE des interpréteurs et serveurs

Les images officielles ci-dessous ont été exportées avec Docker puis inventoriées
avec `vigievuln collect image.tar --output inventaire.json`. La recette a consulté
NVD par produit et version sur le poste auditeur, puis rejoué chaque inventaire
avec `vigievuln analyse inventaire.json --offline --lang fr`. Pour Apache installé
par Debian, la recette a aussi importé le catalogue OSV Debian et utilisé la
version complète du paquet.

| Image | Constat dans « Système hôte », premier sous-chapitre CVE |
| --- | --- |
| `httpd:2.4.49` | CVE-2021-41773 et CVE-2021-42013 sur `/usr/local/apache2/bin/httpd`. |
| `httpd:2.4.51` | Les deux CVE précédentes sont absentes après consultation de NVD pour cette version. |
| `php:7.4.0-fpm` | CVE-2022-37454 sur `/usr/local/sbin/php-fpm`, `/usr/local/bin/php` et `/usr/local/bin/phpdbg`. |
| `php:7.4.33-fpm` | CVE-2022-37454 est absente après consultation de NVD pour cette version. |
| `php:8.2.12-apache-bookworm` | `/usr/sbin/apache2` appartient à `apache2-bin` 2.4.57-2. L’avis Debian lié à CVE-2024-38476 indique le correctif 2.4.61-1~deb12u1. |

Les bornes de correction ont été contrôlées auprès des éditeurs.
[Avis de sécurité Apache 2.4](https://httpd.apache.org/security/vulnerabilities_24.html),
[PHP 7.4.33](https://www.php.net/ChangeLog-7.php#7.4.33) et
[suivi Debian de CVE-2024-38476](https://security-tracker.debian.org/tracker/CVE-2024-38476).


### Contre-recette indépendante sur deux images d’applications publiques

Vibe a exporté chaque image Docker, exécuté la collecte, puis comparé les versions et les chemins avec les fichiers des couches. L’analyse s’est exécutée sur le poste auditeur. Les digests ci-dessous désignent les manifestes publics utilisés le 25 novembre 2026.

| Image Linux amd64 | Manifeste | Contrôle direct |
| --- | --- | --- |
| Ghost 6.79.0, Debian 12 | `sha256:abfa44b1827e514bce3ef1f5e1471bb7c7fd885d9e6316cd648a8b8b883808f0` | 88 paquets dpkg, Node 22.23.5, deux lockfiles pnpm multi-documents, thèmes Casper et Source. |
| Redmine 6.1.6, Alpine 3.24 | `sha256:6ebc1507c3bc5a72bffaf966b3275abb11ea3ddbf6c17289526f3bf2f341e730` | 139 paquets APK, Rails 7.2.4, arborescence Redmine et métadonnées des gems installées. |

Le rapport Ghost associe la priorité Debian `unimportant` à l’avis glibc `DEBIAN-CVE-2019-1010022`. Le rapport Redmine indique le correctif amont 5.9.1 pour `doorkeeper` 5.8.2. Pour les bibliothèques Python fournies par APK, une correspondance OSV amont reste une observation distincte tant que le correctif du paquet Alpine ne peut pas être établi. L’archive Java de la gem `concurrent-ruby` ne fournit pas de coordonnées Maven exploitables. La présence de fichiers ou d’une version dans un lockfile ne démontre pas leur chargement en production.

Le rejeu hors ligne des deux inventaires sur cette version fournit 683 occurrences actives et 329 identifiants d’avis distincts pour Ghost, puis 156 occurrences et 131 identifiants pour Redmine. Les identifiants d’avis peuvent désigner des bulletins de distribution ou des GHSA. Parmi les constats rattachés aux projets, 12 sont directs et 77 indirects sur Ghost, 7 directs et 54 indirects sur Redmine.

Un contrôle indépendant du comparateur sur la configuration NVD publiée de CVE-2023-47260 retrouve les deux bornes de Redmine. Le verdict est positif pour 4.2.10 et 5.0.5 et négatif pour 4.2.11, 5.0.6 et 6.1.6, en accord avec les bornes de l’éditeur. Ce contrôle exerce les règles de version sur une fiche réelle. [Bulletin Redmine](https://www.redmine.org/projects/redmine/wiki/Security_Advisories)

La recette indépendante a rejoué les deux collectes et les deux analyses hors ligne avec le binaire glibc de SHA-256 `d595fb5c833f131eae2a3a1336f87094cc1a7072dfcfffb2ea389df15c863eed`. Le correctif proposé pour un avis se lit dans le contexte de l’application. Par exemple, Redmine 6.1.6 verrouille Rails 7.2.4 ; une borne OSV d’Action Pack dans la branche 8.x doit être examinée lors de la mise à jour de Redmine et de son lockfile. Pour interpréter le cycle de support depuis le JSON, utiliser `supportPhase` et `securitySupportUntil` avec le statut historique.
