# TODO — continuité des données publiques de vulnérabilité

Établi le 13 octobre 2026 après lecture de l'architecture et des implémentations.
Cette liste décrit les travaux à réaliser ; elle ne constitue pas une validation de production.

## Direction retenue

Construire une infrastructure française/européenne qui conserve, actualise et
redistribue les connaissances publiques sur les vulnérabilités. L'accès public gratuit
à ces connaissances est un engagement du projet. Les services professionnels pourront
financer l'exploitation, les instances privées, l'intégration et le support.

Le service doit rester exploitable si une source devient indisponible et permettre
à une organisation de récupérer ses données et de continuer de façon autonome.
La provenance sert à vérifier l'information et à comprendre ses évolutions.

Priorités : **P0** avant d'engager une promesse de continuité ; **P1** pour ouvrir un
pilote public fiable ; **P2** pour la suite. Les objectifs chiffrés ci-dessous sont
des propositions à valider en fonction du volume et des moyens d'exploitation.

## Déjà présent — à compléter, pas à reconstruire

- Sources et indications de licence sur les fiches ; page `/sources` et état des jobs.
- Ingestion CVE List, NVD, OSV, CERT-FR et signaux KEV/EPSS/EUVD.
- Dates de modification et état courant des données ; ce n'est pas un historique complet.
- Dumps publics/privés/complets, deltas, empreintes SHA-256 et signature Ed25519
  configurable ; restauration et diffusion HTTPS/torrent.
- Sauvegarde cohérente SQLite, rétention et planification systemd/Docker.
  PostgreSQL nécessite aujourd'hui une procédure externe (`pg_dump` ou snapshots).
- Branding configurable : nom, slogan, logo, couleurs, mentions éditeur/hébergeur.

## 1. Provenance et conservation des sources — P0

- [ ] **SRC-01 — Registre des sources.** Attribuer un identifiant stable à chaque
  source et décrire producteur, distributeur/mirroir, URL d'origine, endpoints,
  conditions et attribution, cadence attendue, mécanisme de collecte et solution
  de secours. Distinguer par exemple NVD de son distributeur FKIE/GitHub.
- [ ] **SRC-02 — Provenance par révision.** Enregistrer l'identifiant d'origine,
  l'URL, les dates de publication/modification amont, la date de récupération,
  l'empreinte du contenu et l'identifiant de l'import. Conserver séparément la
  version du parseur et la date d'intégration locale.
- [ ] **SRC-03 — Archives brutes.** Conserver les contenus reçus avant projection
  ou troncature, dédupliqués par empreinte, avec une politique de rétention chiffrée.
  Permettre de retraiter un import sans contacter la source. Séparer strictement
  ces archives publiques des requêtes, caches et identifiants privés des clients.
- [ ] **SRC-04 — Intégrité de l'ingestion.** Vérifier les empreintes/signatures
  amont lorsqu'elles existent ; calculer une empreinte locale sinon. Signaler
  distinctement « intégrité vérifiée » et « origine authentifiée ». Ne pas promouvoir
  un import incomplet ou invalide en nouvelle référence saine.
- [ ] **SRC-05 — Désaccords et corrections.** Conserver les assertions de chaque
  source (CVSS, versions affectées, statut, références), y compris leurs désaccords.
  Documenter la règle qui produit la fiche agrégée et séparer les corrections locales.
- [ ] **SRC-06 — Consultation et export.** Exposer la provenance structurée dans
  l'API, les fiches et les dumps ; embarquer les attributions et les références des
  conditions des sources pour qu'un export reste compréhensible hors ligne.

**Critère de livraison :** pour une CVE, remonter de chaque information affichée à
sa source et à l'import correspondant, puis reconstruire la fiche depuis les
archives locales sans accès réseau.

## 2. Historique des mises à jour — P0

- [ ] **UPD-01 — Journal durable des imports.** Ajouter une entrée par exécution,
  sans écraser la précédente : source, début/fin, résultat, curseur ou release,
  volumes lus/ajoutés/modifiés/rejetés, erreurs et version du service.
- [ ] **UPD-02 — Révisions des enregistrements.** Conserver les versions successives
  des CVE, avis et signaux ainsi que les liens modifiés. Une donnée inchangée ne
  crée pas une nouvelle révision ; une nouvelle observation peut être enregistrée.
- [ ] **UPD-03 — Différences lisibles.** Afficher les changements de score, statut,
  versions affectées, correctifs, exploitation connue et références. Identifier
  la source et la date de chaque changement.
- [ ] **UPD-04 — Retraits et suppressions.** Représenter explicitement les CVE
  rejetées, avis retirés et liens supprimés. Les propager dans les deltas sans
  effacer l'historique ; ne pas confondre disparition d'un flux et retrait confirmé.
- [ ] **UPD-05 — Fraîcheur mesurable.** Séparer dernière tentative, dernière collecte
  réussie, version/date du flux amont et dernière modification de l'enregistrement.
  Un job exécuté aujourd'hui ne doit pas rajeunir artificiellement un flux ancien.
- [ ] **UPD-06 — Alertes et état dégradé.** Définir des seuils par source pour retard,
  échecs répétés et variations anormales de volume. Publier les lacunes connues sur
  `/sources` et dans les exports. Ajouter les métriques et alertes d'exploitation.
- [ ] **UPD-07 — Historique public.** Ajouter un historique par fiche et un flux
  de changements paginé avec curseur stable. Exclure toute activité des clients.

**Critère de livraison :** rejouer deux imports identiques sans dupliquer les
révisions ; appliquer une correction puis un retrait et retrouver leurs états
successifs, y compris après transfert par dump complet puis delta.

## 3. Sauvegardes et reprise — P0

- [ ] **BAK-01 — Définir le périmètre.** Inventorier base, archives brutes, dumps,
  configuration, tokens/sels, clés de signature et versions applicatives. Distinguer
  sauvegarde d'exploitation et export public : un dump public ne restaure pas tout.
- [ ] **BAK-02 — Copie hors machine.** Automatiser la copie chiffrée vers un second
  emplacement français/européen indépendant ; ajouter une copie immuable ou hors
  ligne, avec des identifiants distincts de ceux du serveur de production.
- [ ] **BAK-03 — Rétention et objectifs.** Proposition initiale : 7 quotidiennes,
  4 hebdomadaires et 12 mensuelles ; perte maximale de 24 h de données locales et
  remise en service en 4 h. Mesurer coûts et délais avant de contractualiser.
- [ ] **BAK-04 — PostgreSQL.** Documenter et automatiser sauvegarde/restauration
  cohérentes ; prévoir l'archivage WAL si une reprise à un instant précis est requise.
- [ ] **BAK-05 — Clés et secrets.** Prévoir sauvegarde séparée et chiffrée des clés,
  récupération des secrets, rotation/révocation et distribution des empreintes de
  confiance. Exclure ces éléments de tous les exports publics et clients.
- [ ] **BAK-06 — Exercice de restauration.** Restaurer périodiquement sur une
  machine vierge, sans accès aux sources ; vérifier intégrité, recherche, API,
  signatures et contrôle d'accès. Consigner durée, date et résultat.
- [ ] **BAK-07 — Surveillance.** Alerter sur sauvegarde absente, copie distante
  échouée, taille anormale, disque plein ou dernier exercice de reprise trop ancien.

**Critère de livraison :** reconstruire le service après perte complète du serveur
principal à partir des seules copies et procédures, dans les objectifs mesurés.

## 4. Disponibilité autonome et confidentialité — P1

- [ ] **AUT-01 — Mode strict du service.** Interdire les appels amont déclenchés
  par une requête client ; alimenter les données par imports ou synchronisations
  planifiées. Répondre explicitement « donnée absente » ou « ancienne » au besoin.
- [ ] **AUT-02 — Cartographie des sorties.** Documenter destinations, opérateurs
  et informations transmises, notamment miroir Maven Google EU et repli Central.
  Rendre la politique de sortie configurable et testable.
- [ ] **AUT-03 — Continuité des sources.** Prévoir sources/distributeurs alternatifs,
  conservation du dernier état exploitable et procédure de reprise après une longue
  interruption. Une indisponibilité ne doit pas supprimer les données conservées.
- [ ] **AUT-04 — Diffusion autonome.** Rendre obligatoire la signature des publications
  officielles, conserver les bases nécessaires aux deltas et tester un miroir indépendant.
  Vérifier les clés via un canal de confiance distinct du fichier téléchargé.
- [ ] **AUT-05 — Vérification de confidentialité.** Tester que journaux, historiques,
  archives publiques et dumps ne révèlent ni inventaires clients ni secrets ; préciser
  les limites du seuil de publication à K clients.

**Critère de livraison :** source amont coupée, consultation et analyse hors ligne
continuent avec une fraîcheur explicite ; un scan en mode strict ne déclenche aucun
trafic extérieur.

## 5. Nom et identité — P1, en parallèle

- [ ] **NOM-01 — Brief.** Retenir une promesse courte : connaissances publiques sur
  les vulnérabilités, analyse locale et continuité européenne. Choisir une marque
  commune au scanner, au service de données et à une future console.
- [ ] **NOM-02 — Liste courte.** Proposer 5 à 10 noms prononçables en français et
  en anglais ; évaluer clarté, mémorisation, recherche web et absence d'ambiguïté
  avec une autorité publique. Pistes déjà évoquées, non vérifiées :
  « Vigie des dépendances », « Clairdep », « Vulnora ».
- [ ] **NOM-03 — Disponibilité.** Vérifier antériorités pertinentes INPI/EUIPO,
  projets logiciels, domaines, organisations GitHub et noms de paquets. Dater les
  résultats ; ne pas présenter une recherche simple comme une garantie juridique.
- [ ] **NOM-04 — Choix.** Présenter une comparaison courte et faire choisir le nom
  au porteur du projet avant réservation ou changement public.
- [ ] **NOM-05 — Transition.** Commencer par le branding configurable, puis prévoir
  documentation, domaines et éventuels alias de commandes. Préserver la compatibilité
  des API, formats de dumps, chemins de cache et installations existantes.

**Critère de livraison :** nom choisi, vérifications datées et plan de transition
documenté ; le renommage ne casse aucun usage existant.

## 6. Après ces fondations — P2

- [ ] Pilotes avec des utilisateurs ayant des contraintes de confidentialité ou
  de réseau isolé ; recueillir leurs critères de confiance et difficultés réelles.
- [ ] Suivi des projets/SBOM, nouvelles vulnérabilités, notifications et historique
  des décisions de traitement, en maintenant l'analyse locale.
- [ ] Offre d'exploitation : instances privées, support, intégration CI, puis SSO
  et rôles selon les besoins des pilotes.

## Ordre de réalisation proposé

1. Registre des sources + modèle des imports/révisions (`SRC-01/02`, `UPD-01/02`).
2. Conservation brute et intégrité ; copie hors machine et premier exercice de reprise.
3. Corrections/retraits, fraîcheur, historique public et propagation dans les dumps.
4. Mode strict, continuité et vérifications de confidentialité.
5. Nom en parallèle ; ouverture du pilote après validation des critères P0/P1 utiles.

Références locales : [spécification](../../../docs/SPEC-fad-service.md),
[exploitation](OPERATIONS.md), [présentation du service](../README.md).
