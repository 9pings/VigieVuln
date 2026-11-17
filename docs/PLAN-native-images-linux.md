# Images natives et binaires Linux : plan de développement

> Document de conception historique, conservé pour la traçabilité. La fonction
> est implémentée dans la version 1.3.0 ; les commandes et limites actuelles sont
> décrites dans [IMAGES.md](IMAGES.md) et les mesures dans
> [BENCHMARK-IMAGES.md](BENCHMARK-IMAGES.md). Les objectifs ci-dessous ne sont pas
> une déclaration de couverture vérifiée.

## Objectif et contraintes

VigieVuln doit analyser le code, les références d'images, les exports Docker/OCI,
les systèmes de fichiers extraits et les binaires Linux sans Docker, VM,
Trivy/Grype, gestionnaire de paquets ou exécution du contenu analysé.
Le même exécutable prépare les données en ligne et les exploite hors réseau.
La présence d'une référence n'est jamais une preuve du contenu d'une image.
Le présent document précède l'implémentation et sert de contrat aux agents Terra.

L'auto-commit des mises à jour constitue un chantier distinct : cette livraison
porte sur les images et les binaires, sujet précisé dans la conversation.

## Étude de l'existant

- Les codecs collectent des dépendances depuis un chemin local. Conserver cette
  compatibilité évite de réécrire tous les parsers autour d'un filesystem virtuel.
- Le scanner binaire filtre par extension avant les signatures ; les ELF sans
  extension sont perdus. Les métadonnées actuelles concernent les PE.
- Les modules Go embarqués doivent rester des occurrences distinctes, sans être
  confondus avec les JAR du chapitre `embedded` ni exclus comme binaires inconnus.
- Les avis applicatifs et comparateurs actuels ne sont pas des comparateurs de
  versions de distributions. Un paquet corrigé par Debian ne doit pas être
  réévalué comme une version upstream non corrigée.
- Les exports JSON/SARIF/CycloneDX, les rapports et la couverture sont réutilisables.
- Le cache et sa préparation par projet existent. Les nouveaux snapshots doivent
  conserver leurs identités, couverture et dates, sans nécessiter les images
  volumineuses après extraction de l'inventaire.
- L'extraction existante de caches utilise parfois `tar` externe : le lecteur
  d'images doit avoir son propre chemin natif, sans subprocess.

## Architecture et points d'extension

Les registres sont des ensembles d'adaptateurs validés, injectables par API. Le
coordinateur appelle des capacités ; il ne branche pas sur des listes de noms de
logiciels. Les constantes normatives (magic bytes, tags ELF/RPM, types OCI) restent
dans les adaptateurs de format. Aucun catalogue de noms de binaires ne fait foi.

1. **Sources d'artefacts** : adaptateurs `probe/open`, archives Docker save, OCI
   archive/layout, archive rootfs et répertoire. `openArtifact(input, options)`
   retourne `{ targets: [{ id, kind, metadata, root }], cleanup() }`. Les roots
   temporaires sont privés, matérialisés sans privilèges et nettoyés même en erreur.
   Plusieurs images/plateformes produisent plusieurs cibles, jamais un root fusionné.
2. **Transport registre** : client OCI Distribution natif, références tag/digest,
   index multiarchitecture, authentification Bearer/Basic explicite, téléchargements
   bornés et vérification des digests. Produit un layout OCI que les sources locales
   savent ouvrir. Hors ligne, aucune résolution ou acquisition réseau.
3. **Contenu** : inventaire OS et applicatif via collecteurs enregistrés ; chaque
   collecteur possède sa détection, ses preuves et sa couverture. Séparer les
   politiques de parcours du dépôt et d'un rootfs (ne pas exclure node_modules,
   vendor ou les répertoires système dans une image).
4. **Binaires** : registre de formats et extracteurs, lecteurs à accès borné,
   signatures indépendantes des extensions pour ELF, métadonnées structurées et
   modules embarqués. L'identité supposée ne devient jamais une version attestée.
5. **Avis** : adaptateurs de sources/snapshots et comparateurs par système de
   versions ; résolution exacte distribution/version/source/binaire/architecture.
   Verdict à trois états : affected, unaffected, unknown. Couverture du corpus
   distincte du verdict. Les données inconnues ne donnent pas un résultat propre.
6. **Présentation** : identité de cible stable, composants et preuves sérialisables,
   résultats réutilisant les exports existants, section artefacts et couverture,
   filtres CI incluant l'incomplétude. Aucun chemin temporaire ne doit fuiter comme
   identité persistante dans un rapport ou un cache.

## Entrées et intégrité des archives

- Détection par structure et signature, pas uniquement par extension.
- Tar/PAX/GNU, gzip et zstd via codecs natifs ou bibliothèques intégrées.
- Application ordonnée des couches ; whiteouts et répertoires opaques traités avant
  les ajouts de leur couche. Prendre en compte les remplacements fichier/répertoire.
- Liens contenus dans la racine, aucun suivi vers l'hôte ; hardlinks validés et
  résolus sans confondre l'ordre des entrées et l'état final.
- Rejeter traversal, descripteurs corrompus, digests invalides et structures
  ambiguës ; signaler les types non analysables. Ne créer ni device ni fifo.
- Limites ressources configurables (volume décompressé, nombre d'entrées, taille
  des métadonnées, profondeur), avec diagnostic explicite : ces garde-fous ne sont
  pas une limite arbitraire au nombre de composants couverts.
- Une archive `docker export` est un snapshot de conteneur, sans prétendre retrouver
  les tags/couches perdus ni le contenu des volumes omis.

## Inventaire Linux et composants applicatifs

- `os-release` lu comme données, jamais sourcé dans un shell ; conserver l'identité
  réelle de distribution, sans assimiler automatiquement `ID_LIKE` à un fournisseur.
- dpkg : paquets réellement installés, epoch/révision, architecture, paquet source
  et version source ; tenir compte de l'ambiguïté des reconstructions binaires.
- APK : base installée, origine/source, version/révision, architecture.
- RPM : parseur de headers indépendant du stockage ; adaptateurs de stockage
  SQLite et autres formats selon leur signature. Un backend non reconnu est une
  couverture incomplète explicite, jamais un inventaire vide réputé complet.
- Collecteurs applicatifs installés (npm, Python, Composer, Ruby, JAR et modules
  Go) séparés des collecteurs de manifests de développement ; pas d'invention de
  dépendance runtime à partir d'un simple fichier source resté dans l'image.
- Les propriétés propriétaire OS / composant applicatif empêchent le double
  matching inapproprié d'un composant patché par la distribution.

## Analyse des binaires

- ELF 32/64 bits, deux endianesses, validation des tables, segments et offsets.
- PT_INTERP, PT_DYNAMIC/DT_NEEDED/DT_SONAME et notes/build-id comme preuves.
- SONAME et build-id ne sont pas des versions de logiciel ; les chaînes libres
  ne suffisent pas à attribuer une CVE.
- Buildinfo Go moderne et ancien, version de toolchain, modules et remplacements.
  Les versions locales/de développement restent indéterminées.
- Clés d'occurrence `binary-module:<fichier>:<module>@<version>` ; ne jamais perdre
  plusieurs modules du même exécutable dans une Map indexée par le fichier seul.
- Compatibilité PE/Mach-O et des recherches par empreinte existantes.

## Données de vulnérabilité et air gap

- Les snapshots portent schéma, source, identité distribution/release, date,
  intégrité et portée complète/partielle. Un fichier d'avis isolé n'est pas une
  base complète. Les sources sont enregistrables, pas codées dans le coordinateur.
- Fournir une acquisition utilisable et un import local ; pas seulement une API
  acceptant des fixtures de tests. OSV fournit des archives par écosystème ; les
  adaptateurs conservent les identités de release et les ranges natifs.
- Comparateurs Debian/RPM/APK exacts avec corpus de cas ; unsupported = unknown.
- Inventaire exportable indépendant du rootfs ; re-scan des mêmes composants
  contre un nouveau snapshot sans transférer à nouveau l'image complète.
- Une résolution tag -> digest est un snapshot daté, jamais l'affirmation que le
  tag désigne encore le même contenu. La plateforme fait partie de l'identité.
- L'accès à des images privées requiert qu'elles soient disponibles dans un
  registre accessible ou une archive ; VV ne construit aucune image.

## Références déclarées et couverture visible

Découverte extensible des références Dockerfile et documents YAML structurés,
avec source, ligne/contexte et variables résolues ou indéterminées. Distinguer
les étapes de build, bases et images de déploiement ; ne pas interpréter du shell.

Le rapport HTML et JSON distinguent :

- **Référence seule** : contenu non vérifié, diagnostic sur l'absence d'inventaire.
- **Image exacte** : digest/identité et plateforme, collecteurs exécutés et limites.
- **Inventaire mémorisé** : identité d'origine, date, portée et données utilisées.
- **Base seulement** : les RUN/COPY et le résultat du build restent non vérifiés.

La couverture inventory/advisories/sources alimente `--fail-on-incomplete` ; une
référence sans contenu ne produit jamais un badge « aucune vulnérabilité ».

## Livraison et répartition

1. Agent Terra images : lecteurs/archives/couches, contrats et tests de conformité.
2. Agent Terra binaires : formats ELF, buildinfo et intégration codec, tests réels
   et malformés ; puis audit des exports et détection.
3. Agent Terra inventaire : paquets installés, comparateurs, sources/snapshots,
   acquisition/import et tests de matching distro-spécifique.
4. Coordinateur : accès registre, références de code, commandes CLI, inventaires
   exportables, rapports/gates, raccordement aux services applicatifs existants.
5. Revue croisée, corrections, suite complète, exécutable compilé si Bun disponible,
   et scénarios CLI hors réseau. Mettre ce document à jour avec résultats mesurés
   et limites restantes plutôt que déclarer une couverture non testée.

## Validation requise

- Archives multicouches, multi-images, multiarchitecture ; gzip/zstd ; whiteout,
  opaque, liens, altérations, quotas, nettoyage après exception.
- ELF sans extension, 32/64/endian, tables tronquées, Go avec remplacements.
- Paquets OS installés/retirés, source/binaire distincts, versions epoch/revision,
  mauvais fournisseur/release, snapshot absent/partiel/retiré/corrompu.
- Ajout d'un adaptateur de test sans modifier le coordinateur : source,
  compression, collecteur, extracteur et comparateur.
- Référence seule visible en HTML/JSON et exit 2 via strict coverage ; distinction
  base/image finale ; stabilité des identités après nettoyage des roots.
- Processus de scan sans PATH contenant Docker/readelf/rpm ; fetch tripwire en
  offline. Les tests ordinaires ne touchent jamais le réseau.
- Aucun changement des fichiers utilisateur non suivis ; aucune publication.

## Références primaires

- OCI images : https://github.com/opencontainers/image-spec
- OCI couches : https://github.com/opencontainers/image-spec/blob/main/layer.md
- Registres : https://github.com/opencontainers/distribution-spec/blob/main/spec.md
- Docker save : https://docs.docker.com/reference/cli/docker/image/save/
- Docker export : https://docs.docker.com/reference/cli/docker/container/export/
- Go buildinfo : https://go.dev/src/debug/buildinfo/buildinfo.go
- RPM headers : https://rpm.org/docs/4.20.x/manual/format_header.html
- OSV sources et dumps : https://google.github.io/osv.dev/data/
- Debian security tracker : https://security-team.debian.org/security_tracker.html

## État d'exécution

Implémentation réalisée avec trois agents Terra ; guide opérationnel dans
[`IMAGES.md`](IMAGES.md). Les sources d'artefacts, collecteurs, lecteurs RPM,
adaptateurs SBOM, comparateurs, sources et enrichissements disposent de points
d'extension indépendants. La commande `image` orchestre acquisition, inventaire,
évaluation, rapports et filtres CI. Les scans de code signalent les références
d'images dont le contenu n'a pas été inspecté.

Le chemin SQLite d'export/import du cache utilise désormais tar/gzip intégrés,
sans commande `tar` externe. Les nouveaux snapshots et inventaires voyagent dans
le cache existant. Les rapports conservent les relations OSV `upstream` distinctes
des alias ; KEV/EPSS/NVD utilisent les identifiants CVE explicitement déclarés.

### Validation mesurée le 5 novembre 2026

- Suite complète finale : 2 064 tests, 2 053 réussis, 11 ignorés, aucun échec,
  après les corrections SBOM/upstream (98,8 secondes).
- Tests ciblés supplémentaires : 35 réussis pour upstream/enrichissements/exports,
  10 pour le repli SBOM lorsque le paquet source n'est pas identifié.
- Compilation Bun Linux réussie ; scan et sept formats de rapports produits avec
  `PATH=/nonexistent`. Export/import du cache également validés sans outils système.
- Debian `bookworm-slim`, Linux amd64,
  `sha256:a3bba7dc7dbcc1f37c2856c51fc9a7fac96608f50cb87b1b4e4d8b8c85ae988e` :
  783 composants, 216 constats, 213 scores EPSS disponibles. Identités, versions,
  avis, gravités, KEV et EPSS identiques entre le scan connecté et sa reprise
  hors ligne avec les mêmes données. Les liens de répertoires merged `/usr`
  conservent l'appartenance aux paquets sans transférer celle d'un lien fichier.
- Alpine `3.20`, Linux amd64 : scan du contenu, découverte d'un SBOM éditeur et
  import hors ligne validés. Un SBOM sans identité de paquet source reste partiel ;
  le mode préférentiel revient aux couches. Un index dont seules sept des huit
  plateformes ont un SBOM ne perd pas la huitième plateforme.
- Lecteurs RPM éprouvés aussi sur des bases réelles NDB SUSE et Berkeley DB CentOS ;
  cela ne constitue pas une validation de leurs sources de vulnérabilités.
- `git diff --check` sans erreur. Aucun commit ni publication.

### Limites explicites conservées

Une signature de SBOM n'est pas encore vérifiée cryptographiquement. Un inventaire
éditeur conserve donc son origine et ses limites. Un binaire arbitraire dépourvu
de métadonnées ne devient pas identifiable par son seul SONAME ou son nom.
Un Dockerfile ne permet pas de reconstituer fidèlement une image finale sans
ses fichiers construits. Les distributions dont le dépôt/produit ne peut pas être
déduit exactement (notamment SUSE/openSUSE et RHEL) nécessitent une portée d'avis
explicite ; aucune assimilation approximative ne produit un verdict propre.

Les quantités ci-dessus décrivent les snapshots testés, pas une propriété durable
des tags ou une garantie d'exhaustivité sur toutes les images publiques.

## Audit complémentaire des parcours et comparatifs

La demande suivante a étendu la validation aux chemins existants : direct,
flotte, serveur et préparation du cache depuis un inventaire. Cet audit a trouvé
et corrigé le contournement de l'initialisation réseau par la nouvelle commande
`image`, ainsi que le raccordement des avis OS au protocole des fournisseurs.
Les caches conservent maintenant leur origine de proxy jusque dans l'export/import
avec `--cache-dir`. Le mode hébergé utilise des consultations ciblées plutôt que
les archives complètes interdites par le service.

Les deux comparatifs réels sont dans [`BENCHMARK-IMAGES.md`](BENCHMARK-IMAGES.md).
Les transports et le transfert hors ligne reproduisent les mêmes constats ;
la couverture des vulnérabilités reste imparfaite, notamment pour l'historique
Debian 11 et l'identification de la version du programme principal Traefik.
Les services ont été testés localement avec la bibliothèque CLI mise à jour ;
aucun déploiement du service hébergé n'a été réalisé.

## Extension de couverture après comparaison — 5 novembre 2026

Les écarts mesurés sont traités par des adaptateurs de sources indépendants, sans
intégration de Trivy ou Grype au scanner. Le contrat commun renvoie des constats,
des observations indéterminées, la couverture et les échecs de consultation.
L'absence de borne de version reste distincte d'une indisponibilité réseau.

- Historique Debian : découverte de la fin de support et sélection d'un commit
  immuable du tracker ; lecture des listes CVE, DSA et DLA avec portée propre à
  la release. Les correctifs de sid ne deviennent pas des correctifs de stable.
  Un moteur de projection réutilisable conserve le snapshot complet côté serveur
  et transmet les blocs des paquets demandés, avec hash et date de la source.
- Go : les métadonnées VCS embarquées, les labels OCI nécessaires et le document
  de version du proxy de modules doivent concorder pour identifier un programme
  principal marqué `(devel)`. Un tag d'image seul ne prouve pas sa version.
  Les contradictions invalident la preuve ; une panne permet un repli explicite
  sur une preuve antérieure validée. Aucun binaire inspecté n'est exécuté.
- Alpine : le tracker est consulté indépendamment d'OSV. Ses candidats CPE et ses
  statuts par dépôt restent des observations quand la version installée n'est pas
  délimitée. Les paquets binaires issus du même paquet source sont regroupés.
- Fournisseur : les avis XML officiels NGINX sont comparés uniquement aux paquets
  dont les métadonnées déclarent une origine fournisseur cohérente. Ces paquets
  ne reçoivent pas de verdict Debian. Les contraintes de configuration, la preuve
  déclarative et l'absence de vérification de signature restent explicites.

Chaque adaptateur possède sa validation, ses limites de lecture, sa stratégie de
cache et ses règles de version. Les opérations réseau sont typées et passent par
les fournisseurs existants : direct, proxy de flotte et serveur hébergé. Les
snapshots et preuves SQL sont exportables pour le rejeu hors ligne. Les tests de
transport utilisent de vrais services HTTP locaux avec réponses primaires figées.

Les rapports placent les preuves dans les encarts CVE et les observations sans
verdict dans le chapitre de couverture, sans augmenter les compteurs de
vulnérabilités. JSON, CycloneDX, CSAF et SARIF conservent la provenance. Les deltas
vérifient le collecteur ayant réellement produit le constat ; une source manquante
ou une comparaison indéterminée ne constitue pas une correction.

Les résultats réels et les écarts persistants sont consignés dans
[`BENCHMARK-IMAGES.md`](BENCHMARK-IMAGES.md) et son dossier `recall/` de preuves.
L'historique Debian s'arrête à sa date limite ; la cohérence de métadonnées Go
n'est pas une preuve de compilation reproductible. Ces limites restent applicables
même lorsque toutes les consultations techniques ont réussi.

Validation finale de l'extension : 2 236 tests CLI réussis, 11 ignorés ; 585 tests
serveur réussis ; exécutable Linux compilé, rejeu sans outils dans le PATH et zéro
tentative réseau sur les deux images en mode hors ligne. Les nouveaux rapports
et le serveur sont actualisés ; le reçu figure dans le dossier de preuves `recall/`.

## Correction de rappel après audit contradictoire

Le comparatif précédent révélait un défaut du scanner, et pas uniquement un manque
de données : le lecteur Debian n'appliquait pas l'héritage de la note source vers
les releases. Il traitait aussi des décisions de maintenance et l'urgence
`unimportant` comme des raisons d'exclure des constats. Le parseur v2 suit l'ordre
de calcul de `security_db.py` : note générale, exceptions de release et versions
DSA/DLA, sans confondre urgence, version affectée et disponibilité d'un correctif.
Les anciennes entrées de cache restent lisibles mais doivent être préparées de
nouveau pour acquérir les notes auparavant ignorées.

Le matcher de versions natif corrige sa borne ouverte `0` pour les plages semver.
L'index CVEProject et son protocole de proxy deviennent génériques par identité
explicite de paquet, avec index SQL et état de couverture conservé. Les avis GitHub
du dépôt éditeur peuvent compléter OSV quand ce dépôt est relié au binaire par la
preuve Go existante. Une référence GHSA dans une fiche CVE est conservée comme
relation ; elle n'est pas automatiquement transformée en alias.

Les avis ELA publics de Freexian apportent des versions correctives propres à la
release après sa fin de support LTS. Leurs pages publiques, leur pagination et leur
source package sont validés ; l'API CSAF qui exige une authentification n'est pas
utilisée. La comparaison utilise le seuil de correction publié, comme pour les
DSA/DLA, sans inventer de borne d'introduction. Le besoin d'accès au dépôt Extended
LTS est visible. Les preuves de sources différentes survivent à leur fusion dans
les rapports et exports.

Les candidats du tracker courant pour une release retirée restent séparés des
constats confirmés : les exemptions d'une autre release et les bornes upstream
sont du contexte, sans supposer l'absence de rétroportage. Le comparatif conserve
les écarts bruts, puis documente les contradictions et les incertitudes. Les
snapshots précédents ne sont pas remplacés ; la nouvelle passe utilise des copies.

### Diagnostic des consultations via proxy

Le diagnostic sépare l’ancienneté d’une donnée, l’incertitude d’une correspondance
et l’échec concret d’une consultation. Le protocole de cache indique si une réponse
ancienne accompagne une actualisation en cours ou un rafraîchissement échoué.
Une date ancienne ou une réponse historique négative ne suffit pas à déclarer une
source indisponible. Les candidats à identité ou version indécidable restent dans
le contexte de couverture.

Les échecs de requêtes portent une empreinte de leur fournisseur, opération et
paramètres, sans URL ni secret. Une alerte générale n’est retirée que si toutes ses
requêtes échouées sont déjà expliquées par des alertes détaillées. Le refus du
budget amont du proxy est distingué d’un HTTP d’origine et conserve le délai
Retry-After lorsqu’il est fourni. Les tests couvrent les réponses négatives NVD,
les caches simples et par lots, les revalidations et vrais échecs, et la distinction
entre catalogue EUVD disponible et détails partiellement indisponibles.

### Miroir EUVD et réutilisation optionnelle des fiches

Le serveur collecte les métadonnées du catalogue ENISA par pages validées, avec
checkpoint transactionnel et lease. Le premier parcours est suivi de fenêtres
incrémentales recouvrantes et d’un nouveau parcours hebdomadaire. Les paramètres
`jobs.euvdDetails` bornent pages, taille des pages, espacement et octets par réponse.
Le catalogue paginé n’est pas un snapshot atomique garanti ; sa progression reste
explicite. Les relations enrichies de `/enisaid` ne sont pas promises par les
métadonnées de recherche. Les fiches déjà collectées sont immédiatement servies
localement, avec observation et contrôle séparés, sans requête individuelle induite
par leur seul âge.

Le CLI respecte les limitations temporaires et `Retry-After`, avec un budget
par requête (`--proxy-rate-limit-wait-ms`, 45 secondes par défaut), et au plus
15 reprises. L’épuisement de ce budget arrête uniquement les reprises de la requête
concernée ; les autres conservent leur budget. Les attentes sont coordonnées entre
requêtes concurrentes, et S/Échap permet de passer les reprises restantes. Aucun accès direct implicite ne contourne le profil proxy.

La réutilisation des anciennes fiches est activée par défaut. Les fiches
individuelles NVD, OSV/GHSA et EUVD non modifiées depuis le seuil
`--stable-advisory-age-days` (365 par défaut) sont réutilisées. `--no-reuse-stable-advisories` rétablit les
durées normales du cache ; `--reuse-stable-advisories` réactive ce comportement. Les dates
absentes, invalides ou futures ne permettent pas ce raccourci ; les preuves proxy
restent liées à leur origine. Les requêtes par paquet, catalogues, KEV et EPSS
continuent à être actualisés. `--force-update` reste prioritaire et transmet une
revalidation typée au proxy, sous ses budgets habituels. Un échec conserve la copie
utilisable en signalant la cause réelle, sans changer son horodatage.

PostgreSQL/MySQL comme backend du cache CLI : reporté à une autre demande, à la
demande de l’utilisateur ; aucun développement engagé pour cette extension.

La limite demandée est de 15 reprises, espacées d’au moins trois secondes ;
Retry-After reste prioritaire. En terminal interactif, S/Échap permet de passer
l’attente tout en préservant les données disponibles et les diagnostics des
consultations non abouties. Le mode non interactif ne lit pas le clavier.

La passe de validation du 6 novembre ajoute les statuts du tracker Freexian ELTS et
leur conciliation avec les observations Debian par identité exacte. Les conclusions
et les limites, notamment les 154 écarts bruts NGINX–Trivy dont 77 non affectés et
77 indéterminés, sont documentées dans les [preuves du rejeu](benchmark-evidence/2026-11-06-images/elts/README.md).
