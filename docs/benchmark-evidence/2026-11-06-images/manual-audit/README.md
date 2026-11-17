# Vérification manuelle de cinq écarts NGINX — 6 novembre 2026

Échantillon choisi parmi les 77 tuples encore indéterminés, pour couvrir bornes amont, options de compilation et régression introduite par backport. Il n'est pas représentatif statistiquement. Vérification statique : aucune exploitation exécutée et aucune modification du matcher ou des compteurs du benchmark.

| CVE | Composant installé | Conclusion de l'audit |
| --- | --- | --- |
| CVE-2026-18924 | curl/libcurl4 7.74.0-1.3+deb11u11 | Détection justifiée pour **libcurl4**. L'éditeur liste 7.74.0 parmi les versions affectées et exige HTTP/2 push avec partage de connexion. L'outil curl lui-même est explicitement exclu par l'avis : ne pas confondre le périmètre bibliothèque et celui de l'exécutable. |
| CVE-2026-19931 | curl/libcurl4 7.74.0-1.3+deb11u11 | Détection justifiée : version dans la plage affectée depuis 7.64.1, avec utilisation conditionnelle de Negotiate et de connexions réutilisées. Le build Debian active GSSAPI. |
| CVE-2026-84782 | libssl1.1/openssl 1.1.1w-0+deb11u1 | Détection justifiée : OpenSSL déclare la branche 1.1.1 affectée et donne 1.1.1zj comme correction. La révision Debian installée date du 13 septembre 2023 et ses six patches ne corrigent pas le chemin DTLS concerné. L'exploitation dépend de l'utilisation de DTLS ; elle n'est pas démontrée dans NGINX. |
| CVE-2026-82208 | curl/libcurl4 7.74.0-1.3+deb11u11 | Correspondance Trivy non justifiée pour cette image : introduction en 8.9.1 et dépendance à wolfSSL. Le paquet 7.74.0 est antérieur ; Debian indique en outre ne pas compiler curl avec wolfSSL. |
| CVE-2026-76781 | libxml2 2.9.10+dfsg-6.7+deb11u4 | Correspondance Trivy non justifiée pour cette révision. Debian décrit une régression introduite par le backport de CVE-2026-0992. Le tarball source exact et les patches Debian vérifiés ne contiennent pas la boucle de déduplication `nextCatalog` fautive. Le code d'origine protège déjà la suite par un test de nullité. |

Sources curl : [18924](https://curl.se/docs/CVE-2026-18924.html), [19931](https://curl.se/docs/CVE-2026-19931.html), [82208](https://curl.se/docs/CVE-2026-82208.html). Leurs [métadonnées JSON](https://curl.se/docs/CVE-2026-18924.json) contiennent des bornes de versions structurées et un périmètre bibliothèque/exécutable. La [révision Debian exacte](https://salsa.debian.org/debian/curl/-/tree/debian/7.74.0-1.3+deb11u11/debian) date du 10 décembre 2023 ; sa série de patches et ses options HTTP/2/GSSAPI ont été contrôlées. Cette vérification des sources ne constitue pas un test d'exploitation ni une certification du binaire.

Sources OpenSSL : [avis du 29 septembre](https://openssl-library.org/news/secadv/20260929.txt), archive Debian exacte référencée dans [source-hashes.json](source-hashes.json).

Sources libxml2 : [avis Debian](https://security-tracker.debian.org/tracker/CVE-2026-76781), [correctif amont](https://github.com/GNOME/libxml2/commit/c63248941708bc1d2e3a4292954593312212f6ca). Le fichier `catalog.c` du tarball Debian original est identique à celui du tag amont 2.9.10 (SHA-256 `070507a77a11c0924046d7a9896b49c0cae7bdd6a349589d8c5d429bdd1975d2`) ; aucun patch de la révision deb11u4 ne touche ce fichier. La révision est datée du 15 avril 2023.

## Conséquence pour VV

Trois CVE de cet échantillon justifient une détection dans l'image et deux ne la justifient pas. Le passage au statut indéterminé n'est donc pas toujours la bonne conclusion finale. Le refus de déduire automatiquement qu'un ancien paquet est affecté depuis le seul statut d'une révision plus récente évite effectivement des faux positifs, mais doit être complété par les bornes amont et le contexte Debian. Une règle qui accepterait tous les anciens paquets recréerait notamment le faux positif libxml2.

Les sources existent : une partie du défaut est dans leur exploitation et leur conciliation, pas uniquement dans leur disponibilité. Les champs amont (introduction, correction, périmètre, capacités requises) et les modifications propres à la distribution doivent rester distincts et traçables.

Les dates du message précédent provenaient des champs `PublishedDate` du rapport Trivy. Les avis curl contrôlés sont publiés par l'éditeur le 2 septembre 2026 : les dates d'agrégation ne doivent pas être présentées comme la première publication de l'éditeur.
