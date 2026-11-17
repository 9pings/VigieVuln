# Images : preuve Freexian ELTS — 6 novembre 2026

Ce dossier conserve les résultats du rejeu des inventaires OCI déjà figés le 5 novembre. Les images n'ont pas été exécutées. Les fichiers compressés sont les exports JSON intégraux des scans ; leurs comparaisons sont recalculées avec `scripts/compare.cjs` à partir des sorties Trivy et Grype originales. Les données d'entrée et les versions des comparateurs sont décrites dans la [preuve du 5 novembre](../../2026-11-05-images/reduction/README.md).

| Image | Findings VV | Tuples CVE Trivy communs / total | Tuples CVE Grype communs / total |
| --- | ---: | ---: | ---: |
| NGINX Debian 11 | 739 | 634 / 788 | 598 / 600 |
| Traefik Alpine | 285 | 204 / 204 | 155 / 206 |

La différence brute NGINX–Trivy reste de **154 tuples**. L'examen des 185 tuples anciennement résiduels distingue 31 tuples désormais confirmés, 77 non affectés selon les preuves Freexian pour Bullseye, et 77 encore indéterminés. Les 77 non-affectés restent dans la différence brute de 154 ; ils ne constituent pas des vulnérabilités confirmées. L'identité des tuples et les preuves de chaque évaluation figurent dans [residual-assessment-summary.json](residual-assessment-summary.json). Les 175 observations complémentaires du rapport NGINX comprennent les résultats négatifs, les états indéterminés et d'autres observations ; elles ne sont pas ajoutées aux 739 findings.

La photographie du [tracker Freexian](https://deb.freexian.com/extended-lts/tracker/data/json) utilisée a pour SHA-256 `132cd4b4671ca30e143c3e5aae0c89f9e2df4bc1a72c5e06e709e7aaaa1d2a3d`. Le dump complet n'est pas reproduit ici ; [release-pages-index.json](release-pages-index.json) conserve les empreintes et dates des fiches ciblées, et les exports JSON conservent les preuves nécessaires aux évaluations. La version source, la distribution et la CVE sont conciliées exactement ; les divergences entre sources ne sont pas effacées.

Pour Traefik, 46 des 51 tuples Grype non identiques possèdent une relation documentée au même binaire ; cinq restent sans rapprochement établi. Ces 46 relations ne sont pas comptées parmi les 155 égalités de tuples. Les analyses NGINX et Traefik ont été rejouées hors ligne avec respectivement 739 et 285 findings et **zéro tentative réseau**, comme l'indiquent les journaux conservés ici. NGINX a également été rejoué avec l'exécutable autonome. Chaque rapport conserve un avertissement historique EUVD 403 : 28 fiches NGINX et 11 Traefik n'avaient pas été obtenues ; le rejeu ne les présente pas comme des consultations réussies.

La suite CLI après le correctif mémoire rapporte 2 348 tests : 2 337 réussis, 11 ignorés, aucun échec ; la suite serveur rapporte 599 réussites. Ces mesures caractérisent les données et l'état du code de ce rejeu, sans prétendre à une couverture exhaustive ou à l'absence de faux positifs.

Pour recalculer à partir des entrées locales inchangées, placer `nginx` et `traefik` sous un même répertoire, avec `inventory.json`, `acquisition.json`, `trivy.json`, `grype.json`, `grype.cdx.json` et un sous-répertoire `final/findings.json`, puis exécuter :

```sh
node docs/benchmark-evidence/2026-11-05-images/scripts/compare.cjs <répertoire-entrées> <répertoire-sortie> final
```

Les rapports HTML correspondants sont [NGINX](../../../samples/nginx-image.html) et [Traefik](../../../samples/traefik-image.html). Les dates de génération des fichiers de comparaison peuvent varier ; les empreintes d'entrée et les comptes doivent correspondre.

Le [test de projection mémoire](snapshot-memory-proof.json) lit le dump réel de 138 188 488 octets avec une limite de heap JavaScript de 192 MiB : un seul téléchargement amont et deux projections isolées (`apt` et `curl`) ont réussi. Cette limite concerne le heap, pas la mémoire totale du processus : le RSS maximal observé est de 528 792 KiB. Ce test valide le correctif local de traitement du dump ; il ne constitue pas une preuve de déploiement en production.

Les métadonnées de registre ont été rétablies uniquement après vérification des empreintes Linux amd64 contre les [observations immuables du 5 novembre](../../2026-11-05-images/image-updates/registry-reference-verification.json). Les inventaires initiaux restent inchangés ; les copies de rejeu sont liées à ces preuves. Les tags observés — Traefik `v2.11.61` disponible sur la branche `v2.11` et NGINX `1.24.0` courant sur la branche `1.24` — datent de cette observation et ne prouvent pas qu’une vulnérabilité est corrigée. Les fichiers `*-published-registry-tripwire.json` prouvent zéro tentative réseau et zéro lancement de processus.

## Livraison et contrôles finaux

Le [déploiement](deployment.json) met à jour web, worker et curation avec la même image immuable ; PostgreSQL et le WAF sont conservés. Le [manifeste des sources](source-manifest.json) enregistre les fichiers effectivement empaquetés, y compris les modifications non commitées. Les deux [points de santé publics](final-health.json) répondent HTTP 200 ; le conteneur web est sain, sans redémarrage depuis ce déploiement.

Le [contrôle réel du relais](live-source-smoke-final.json) a servi les seules fiches `apt` puis `curl`, avec la même empreinte du dump et sa date initiale. Ce contrôle précède le dernier changement CSS, sans modification du code de sources entre les deux images. Son catalogue courant diffère du catalogue figé utilisé pour les comparaisons : les deux empreintes sont conservées séparément. Un premier essai avait révélé un dépassement du heap ; le découpage des entrées et la réduction des copies l'ont corrigé. La [preuve mémoire](snapshot-memory-proof.json) utilise le vrai dump figé de 138 Mo sous une limite de heap de 192 MiB ; cette limite ne désigne pas la mémoire totale du processus.

Les [contrôles du navigateur](browser-check.json) couvrent les deux rapports à 1 440 et 390 pixels, les tables défilantes et les recommandations d'image. Le [rejeu du binaire autonome final](standalone-proof.json), sans Node ni commandes disponibles dans le PATH, retrouve exactement les mêmes résultats CVE et artefacts que Node, références de registre comprises. Les [résultats de validation](validation.json) distinguent les suites complètes des 20 tests de rendu finaux.
