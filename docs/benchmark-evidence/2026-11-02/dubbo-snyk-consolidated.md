# Dubbo : bilan exclusif des 167 écarts Snyk

Unité : un triplet unique **paquet / version / identifiant Snyk**. Les 167 occurrences correspondent à 141 identifiants Snyk distincts. Elles ne représentent ni 167 vulnérabilités indépendantes ni 167 bugs du scanner.

| Groupe initial | Corrigés et retrouvés | Manques confirmés paquet/version | Erreurs Snyk version/module | Déjà signalés, équivalence prouvée | Indéterminés | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Identité absente du snapshot OSV Maven | 12 | 20 | 6 | 0 | 33 | 71 |
| Même paquet, version non retournée | 0 | 22 | 13 | 1 | 2 | 38 |
| Autre coordonnée OSV Maven | 0 | 26 | 5 | 2 | 25 | 58 |
| **Total exclusif** | **12** | **68** | **24** | **3** | **60** | **167** |

Les groupes contiennent respectivement 55, 29 et 57 identifiants Snyk distincts. Un identifiant, `SNYK-JAVA-COMFASTERXMLJACKSONCORE-467016`, a des versions confirmées manquantes et une version indéterminée : on ne peut donc additionner naïvement les nombres d’identifiants distincts par verdict.

Deux décisions explicites corrigent les totaux bruts des revues précédentes :

- Netty `netty-codec-http2@4.1.35.Final`, CVE-2023-44487, est déjà signalé sous GHSA-xpw8-rcwv-8f8p. Le commit amont lie explicitement les identités. Il ne manque pas au même paquet/version.
- Logback `logback-classic@1.2.2`, CVE-2023-6481, relève de l’équivalence expressément déclarée par le mainteneur avec CVE-2023-6378, déjà signalé pour ce paquet/version. La même règle était appliquée à logback-core. Pour cette partition d’incidents, l’équivalence prouvée prévaut sur le désaccord de plage du CVE 6481 ; ce désaccord reste documenté.

Les preuves et motifs sont dans [les deux décisions de consolidation](dubbo-snyk-consolidation-overrides.json). Les revues initiales restent disponibles ; la présente partition les remplace pour les totaux.

Les **12 récupérations** sont vérifiées directement dans le rapport reconstruit v2 par CVE, paquet et version. Elles concernent un défaut de projection/index ancien et sa reconstruction, pas douze bugs indépendants. Le premier rapport élargi les retrouvait déjà avant le contrôle final du schéma v2 : ne pas attribuer à tort douze nouveaux gains à la seule dernière modification du numéro de schéma.

Les **68 manques** prouvent une meilleure couverture des observations concernées par Snyk dans ces scans. Ils ne prouvent pas que sa base est globalement supérieure, ni que tous sont des bugs de code VigieVuln. Certains documents existent dans les sources natives mais manquent d’identité de paquet ou de plages automatiquement évaluables. « Base Snyk plus complète » est donc une explication possible ou un axe d’analyse, pas une sixième catégorie exclusive démontrée. Les 12 cas restant attribués à un autre paquet dans le groupe de 58 sont inclus dans les 68 ; d’autres écarts peuvent avoir le même CVE déjà signalé à une autre version. Ne pas en déduire un nombre de vulnérabilités globalement absentes.

Les **24 erreurs** sont limitées à la version ou au module étudié. Les **60 indéterminés** ne sont comptés ni comme défauts du scanner ni comme fausses alertes. Aucun verdict n’affirme l’exploitabilité dans Dubbo.

[Partition détaillée et empreintes](dubbo-snyk-consolidated.json). Recalcul sans réseau, sans jeton et sans rapport privé :

```sh
python3 scripts/consolidate-snyk.py
```

Le script, lancé depuis n’importe quel répertoire avec son chemin correct, vérifie que les 167 clés sont uniques et correspondent exactement au jeu initial. Il lit les trois revues archivées et les deux décisions de consolidation ; il écrit le JSON sur la sortie standard.
