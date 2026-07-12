# Migration cryptogen → Fabric-CA + PostgreSQL + LDAP

Ce dossier remplace la génération de certificats `cryptogen` de votre script
d'origine par une PKI **Fabric-CA** conteneurisée, en s'inspirant du schéma
d'architecture fourni (CA / base de données / LDAP par organisation).

## Ce qui a changé par rapport à `generate-network.bash`

| Avant (cryptogen) | Maintenant (Fabric-CA) |
|---|---|
| `cryptogen generate` génère tous les certs d'un coup, hors ligne | 1 serveur **Fabric-CA** par organisation (+ 1 pour l'Orderer), démarré dans Docker |
| Pas de stockage des identités | Chaque CA persiste ses identités/certificats dans **PostgreSQL** dédié |
| — | Chaque organisation a son propre **annuaire OpenLDAP**, pré-rempli avec les identités de l'org (admin, orderer/peers, user applicatif) |
| `crypto-config/...` | `organizations/...` (même mise en page : `peerOrganizations/`, `ordererOrganizations/`) |

Le reste (questionnaire interactif, `configtx.yaml`, `docker-compose.yaml`
pour les peers/orderer/CLI, génération des blocs de canaux via
`configtxgen`) fonctionne exactement comme avant.

## Fichiers

- **`generate-network.sh`** — questionnaire interactif (`network.env`),
  génère les `fabric-ca-server-config.yaml` + fichiers LDIF de bootstrap
  LDAP par organisation, le `docker-compose.yaml` complet (Postgres + LDAP
  + Fabric-CA + peers + orderer + CLI) et le `configtx.yaml`.
- **`enroll-network.sh`** — à lancer une fois les CA démarrées. Enregistre
  ("register") puis enrôle ("enroll") toutes les identités auprès de
  chaque Fabric-CA via des conteneurs `fabric-ca-client` jetables, et
  construit l'arborescence `organizations/` (MSP + TLS + `config.yaml`
  NodeOUs) attendue par les peers, l'orderer et `configtxgen`.

## Comment ça correspond au schéma fourni

- **"Cluster of Fabric-CA Servers" / HA Proxy** → simplifié en **1 serveur
  Fabric-CA par organisation** (pas de cluster ni de répartiteur de charge :
  overkill pour un environnement de développement ; le schéma en production
  recommande d'ailleurs 1 CA par organisation plutôt qu'un cluster partagé).
- **MySQL / PgSQL** → **PostgreSQL**, un conteneur dédié par organisation,
  utilisé comme "registry" faisant autorité pour Fabric-CA (stockage des
  identités et certificats émis).
- **LDAP** → un conteneur **OpenLDAP** par organisation, automatiquement
  rempli (LDIF) avec les mêmes identités que celles enregistrées dans la CA
  (admin d'org, peers, orderer, utilisateur applicatif). Il est prêt à
  l'emploi pour un usage applicatif (SSO, lookup d'identité, contrôle
  d'accès côté chaincode/API) — voir la section *Important : LDAP* plus bas.
- **Fabric-CA client / SDK** → remplacé par `fabric-ca-client`, exécuté via
  Docker dans `enroll-network.sh` (pas de binaire à installer sur l'hôte).

## Important : pourquoi LDAP n'authentifie pas directement la CA

Fabric-CA supporte nativement `ldap.enabled: true`, qui bascule le
*registry* de la CA vers LDAP (l'étape `register` disparaît, et l'enrôlement
authentifie directement l'identité par bind LDAP). C'est indiqué en
commentaire dans chaque `fabric-ca-server-config.yaml` généré.

Ce mode a une conséquence importante : le "type" d'une identité (peer,
orderer, admin, client), qui est ce qui permet à **NodeOUs** de gérer les
rôles à partir du certificat, est normalement défini au moment du
`register`. En LDAP-registry, il faudrait recréer ce mapping via des
`converters` LDAP → attributs `hf.*`, ce qui est possible mais fragile
pour un premier déploiement.

Par prudence, ce générateur garde **PostgreSQL comme registry faisant
autorité** (register + enroll classiques, comportement garanti correct
pour NodeOUs), et fait tourner LDAP **en parallèle**, pré-rempli avec les
mêmes identités/mots de passe, pour un usage applicatif immédiat. Si vous
voulez basculer une organisation en mode "LDAP = registry" plus tard,
décommentez le bloc `ldap:` dans son `fabric-ca-server-config.yaml`.

## Ordre de lancement

```bash
./generate-network.sh          # questionnaire + génère tous les fichiers

# 1) Démarrer uniquement la couche PKI (DB + LDAP + Fabric-CA)
docker-compose up -d postgres.orderer ldap.orderer ca.orderer \
                     postgres.org1 ldap.org1 ca.org1 \
                     postgres.org2 ldap.org2 ca.org2   # etc. pour chaque org

# 2) Enregistrer/enrôler toutes les identités -> construit organizations/
./enroll-network.sh

# 3) Générer les blocs de canaux
export FABRIC_CFG_PATH=${PWD}
configtxgen -profile Profile_<canal> \
  -outputBlock ./channel-artifacts/<canal>_genesis.block -channelID <canal>

# 4) Démarrer le reste du réseau (orderer, peers, CLI)
docker-compose up -d

# 5) Rejoindre les canaux comme d'habitude (osnadmin / peer channel join)
```

`enroll-network.sh` est idempotent pour le `register` (les doublons sont
ignorés) ; vous pouvez le relancer sans tout détruire si un peer a été
ajouté après coup.

## Identités créées par organisation

| Identité | Type | Secret | Usage |
|---|---|---|---|
| `orgadmin` | admin | `orgadminpw` | → `users/Admin@<domaine>/msp` |
| `user1` | client | `user1pw` | → `users/User1@<domaine>/msp` (identité applicative) |
| `peer0`, `peer1`, ... | peer | `peer<N>pw` | → `peers/peer<N>.<domaine>/{msp,tls}` |

Pour l'Orderer : `ordereradmin` (admin) et `orderer` (orderer).

⚠️ Ce sont des secrets de développement en clair, cohérents entre
PostgreSQL et LDAP pour que les deux annuaires restent synchronisés. Ne
réutilisez jamais ces valeurs telles quelles en production — voir aussi
`tls.enabled: false` sur les CA (TLS désactivé côté CA pour simplifier le
développement local ; à activer avant tout déploiement réel).

## Prochaines améliorations possibles

- Activer TLS sur les serveurs Fabric-CA eux-mêmes (`tls.enabled: true`)
  et sur les connexions à PostgreSQL.
- Générer des mots de passe aléatoires par identité au lieu de secrets fixes.
- Ajouter un healthcheck Docker natif sur `ca.*` plutôt que le polling fait
  par `enroll-network.sh`.
- Basculer une organisation en LDAP-registry complet avec les `converters`
  nécessaires pour NodeOUs, si vous voulez réellement piloter les rôles
  depuis l'annuaire.
