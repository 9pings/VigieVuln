# Déploiement de la couverture images — 5 novembre 2026

Web, worker et curation utilisent l’image inscrite dans [deployment.json](deployment.json).
Le verrou a été vérifié ; PostgreSQL et le WAF n’ont pas été recréés. Les contrôles
publics du site et de l’API répondent 200 : [health.json](health.json). Les fichiers
exécutés sont décrits par [deployed-source-manifest.json](deployed-source-manifest.json).

Une première tentative a été annulée automatiquement : le filtre sécurisé
d’extraction Python retire les modes des répertoires, et l’umask privé les avait
rendus illisibles pour l’utilisateur du conteneur. L’ancienne image saine a été
restaurée. La préparation corrige maintenant les droits des seuls répertoires
runtime, sous un répertoire de construction privé. Le build et un conteneur sans
réseau vérifient le chargement des modules serveur et CLI avec l’UID 10001 avant
de déployer. Aucun changement du schéma de données n’a été effectué.

Les opérations authentifiées de proxy ont été testées contre les vrais services
HTTP locaux ; les contrôles publics de production ne sont pas présentés comme
un scan authentifié de production.
