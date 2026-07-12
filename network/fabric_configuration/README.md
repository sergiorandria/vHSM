# Création d'un Ledger Node (Blockchain Privée) avec Hyperledger Fabric


Before doing anything stupid! Run this: 
```bash
# Stop and remove everything                                                                                                              
docker-compose down -v

# Remove all generated files
rm -rf crypto-config channel-artifacts network.env configtx.yaml docker-compose.yaml crypto-config.yaml

# Remove any leftover containers
docker rm -f $(docker ps -aq --filter "name=university") 2>/dev/null

# Remove peer/orderer data volumes
docker volume prune -f
```


Ce dépôt contient des scripts automatisés pour déployer un réseau Hyperledger Fabric complet (ledger node/blockchain privée) incluant :
- Génération de la configuration réseau (organisations, peers, orderer, canaux)
- Déploiement des conteneurs Docker (peer, orderer, CLI, chaincode servers)
- Déploiement de chaincodes en mode CCaaS (Chaincode as a Service)

## 🚀 Processus de création du ledger node

### 1. Prérequis
Assurez-vous d'avoir installé :
- Docker et Docker Compose
- Hyperledger Fabric binaries (cryptogen, configtxgen, peer, orderer) dans votre PATH
- Go language (pour la compilation des chaincodes)

### 2. Génération du réseau de base

Lancez le script interactif pour configurer et générer votre réseau :

```bash
./generate-network.bash
```

Le script vous posera plusieurs questions :
- Chemin des binaires Fabric (par défaut: ./bin)
- Domaine de l'orderer (par défaut: example.com)
- Nombre d'organisations de peers
- Pour chaque organisation : nom, ID MSP, domaine, nombre de peers, présence d'un conteneur CLI admin
- Nombre de canaux applicatifs
- Pour chaque canal : nom et organisations participantes

Le script générera automatiquement :
- `network.env` : fichier de configuration des variables d'environnement
- `crypto-config.yaml` : spécification de la génération des matériels cryptographiques
- Matériaux cryptographiques (clés publiques/privées, certificats) dans le dossier `crypto-config/`
- `docker-compose.yaml` : configuration Docker pour déployer le réseau
- `configtx.yaml` : configuration pour la génération des transactions de canal
- Dossier `channel-artifacts/` contenant le bloc de genèse et les transactions de canal

### 3. Démarrage du réseau

Une fois la génération terminée, démarrez le réseau avec Docker Compose :

```bash
docker-compose up -d
```

Cette commande lancera :
- Un conteneur orderer (pour l'ordonnancement des transactions)
- Un conteneur peer par organisation configurée
- Un conteneur CLI admin par organisation (si demandé lors de la configuration)
- Le réseau Docker nommé `fabric` pour la communication entre les conteneurs

### 4. Création et configuration des canaux

Après le démarrage du réseau, vous devez créer les canaux et faire rejoindre les peers :

#### Créer un canal
```bash
# Exemple pour créer un canal nommé "canaltest"
docker exec cli.org1.example.com \
  peer channel create \
  -o orderer.example.com:7050 \
  -c canaltest \
  -f /var/hyperledger/orderer/channel-artifacts/canaltest.tx \
  --outputBlock /var/hyperledger/orderer/channel-artifacts/canaltest.block \
  --tls \
  --cafile /etc/hyperledger/orderer/tls/ca.crt
```

#### Here run osnadmin

#### Faire rejoindre les peers au canal
```bash
# Peer0 de l'organisation 1 (ciblé par défaut)
docker exec cli.org1.example.com \
  peer channel join -b /var/hyperledger/orderer/channel-artifacts/canaltest.block

# Peer1 de l'organisation 1 (surcharge l'adresse)
docker exec -e CORE_PEER_ADDRESS=peer1.org1.example.com:7051 cli.org1.example.com \
  peer channel join -b /var/hyperledger/orderer/channel-artifacts/canaltest.block

# Peer0 de l'organisation 2
docker exec -e CORE_PEER_ADDRESS=peer0.org2.example.com:7051 cli.org2.example.com \
  peer channel join -b /var/hyperledger/orderer/channel-artifacts/canaltest.block
```

#### Vérification de la création du canal
```bash
# Vérifier que le bloc du canal a bien été créé
docker exec cli.org1.example.com ls -la /var/hyperledger/orderer/channel-artifacts/canaltest.block

# Vérifier que le peer a bien rejoint le canal (pour un autre peer)
docker exec -e CORE_PEER_ADDRESS=peer1.org1.example.com:7051 cli.org1.example.com peer channel list

# Obtenir les informations du canal
docker exec cli.org1.example.com peer channel getinfo -c canaltest
```

### 5. Déploiement des chaincodes (mode CCaaS)

Pour déployer des chaincodes sur votre réseau, utilisez le script de configuration des chaincodes :

```bash
./chaincode-config.bash
```

Ce script vous guidera à travers :
1. Sélection des canaux sur lesquels déployer des chaincodes
2. Pour chaque canal sélectionné :
   - Nom et version du chaincode
   - Chemin vers le code source Go du chaincode (peut pointer vers le template fourni ou votre propre code)
   - Génération automatique du Dockerfile pour le chaincode server
   - Construction de l'image Docker du chaincode
   - Déploiement du conteneur serveur chaincode (CCaaS) pour chaque peer
   - Génération des paquets chaincode (.tar.gz) avec metadata et connexion TLS
   - Installation des chaincodes sur les peers correspondants
   - Vérification de santé (healthcheck) des serveurs chaincode

Le script supporte le déploiement de chaincodes en mode CCaaS où chaque chaincode s'exécute dans son propre conteneur Docker séparé, communiquant avec les peers via une interface TLS sécurisée.

### 6. Cycle de vie standard des chaincodes (après installation)

Après l'installation des chaincodes via le script, vous devez suivre le cycle de vie standard de Fabric :

#### Approuver la définition du chaincode pour chaque organisation
```bash
# Exemple pour org1
docker exec -e CORE_PEER_LOCALMSPID=org1MSP -e CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/admin-msp cli.org1.example.com \
  peer lifecycle chaincode approveformyorg \
  -o orderer.example.com:7050 \
  --channelID canaltest \
  --name thesis \
  --version 1.0 \
  --package-id thesis_1.0:$(peer lifecycle chaincode calculatepackageid ./ thesis_1.0.tar.gz) \
  --sequence 1 \
  --tls \
  --cafile /etc/hyperledger/orderer/tls/ca.crt
```

#### Vérifier la prêter à l'engagement (commit readiness)
```bash
docker exec cli.org1.example.com \
  peer lifecycle chaincode checkcommitreadiness \
  -o orderer.example.com:7050 \
  --channelID canaltest \
  --name thesis \
  --version 1.0 \
  --sequence 1 \
  --tls \
  --cafile /etc/hyperledger/orderer/tls/ca.crt \
  --output json
```

#### Engager (commit) la définition du chaincode sur le canal
```bash
docker exec cli.org1.example.com \
  peer lifecycle chaincode commit \
  -o orderer.example.com:7050 \
  --channelID canaltest \
  --name thesis \
  --version 1.0 \
  --sequence 1 \
  --tls \
  --cafile /etc/hyperledger/orderer/tls/ca.crt
```

### 7. Utilisation du chaincode déployé

Une fois le chaincode engagé, vous pouvez l'invoquer pour interagir avec le ledger :

#### Créer une nouvelle enregistrement (ex: thèse)
```bash
docker exec cli.org1.example.com \
  peer chaincode invoke \
  -o orderer.example.com:7050 \
  --channelID canaltest \
  --name thesis \
  --isInit \
  -c '{"Args":["CreateThesis","TH001","18.5","Titre de la thèse","2026-06-28"]}' \
  --tls \
  --cafile /etc/hyperledger/orderer/tls/ca.crt
```

#### Lire un enregistrement
```bash
docker exec cli.org1.example.com \
  peer chaincode query \
  -o orderer.example.com:7050 \
  --channelID canaltest \
  --name thesis \
  -c '{"Args":["ReadThesis","TH001"]}' \
  --tls \
  --cafile /etc/hyperledger/orderer/tls/ca.crt
```

#### Mettre à jour un enregistrement
```bash
docker exec cli.org1.example.com \
  peer chaincode invoke \
  -o orderer.example.com:7050 \
  --channelID canaltest \
  --name thesis \
  -c '{"Args":["UpdateThesis","TH001","19.0","Nouveau titre","2026-06-29"]}' \
  --tls \
  --cafile /etc/hyperledger/orderer/tls/ca.crt
```

#### Lire tous les enregistrements
```bash
docker exec cli.org1.example.com \
  peer chaincode query \
  -o orderer.example.com:7050 \
  --channelID canaltest \
  --name thesis \
  -c '{"Args":["GetAllTheses"]}' \
  --tls \
  --cafile /etc/hyperledger/orderer/tls/ca.crt
```

### 8. Structure du template de chaincode

Le dossier `template_chaincode/` contient un exemple de chaincode en Go pour la gestion de thèses académiques. Il fournit les fonctions CRUD de base :
- `CreateThesis` : Insère une nouvelle thèse
- `ReadThesis` : Retourne une thèse par son ID
- `UpdateThesis` : Met à jour une thèse existante
- `DeleteThesis` : Supprime une thèse
- `GetAllTheses` : Retourne toutes les thèses enregistrées

Vous pouvez modifier ce template ou créer vos propres chaincodes en suivant la même structure.

### 9. Arrêt et nettoyage du réseau

Pour arrêter le réseau :
```bash
docker-compose down
```

Pour supprimer complètement le réseau et toutes ses données :
```bash
docker-compose down -v
# Puis supprimez les dossiers générés :
rm -rf crypto-config channel-artifacts network.env docker-compose.yaml configtx.yaml
```

### 10. Personnalisation avancée

Tous les fichiers de configuration générés peuvent être modifiés manuellement pour des besoins spécifiques :
- `configtx.yaml` : Ajustez les policies, capacités, types d'orderer, etc.
- `docker-compose.yaml` : Modifiez les ressources allouées, ajoutez des monitoring, etc.
- Les chaincodes peuvent être enrichis avec une logique métier complexe

## 📁 Structure du projet

```
network/fabric_configuration/
├── generate-network.bash      # Script interactif de génération du réseau
├── chaincode-config.bash      # Script de déploiement des chaincodes (CCaaS)
├── README.MD                  # Ce fichier
├── docker-compose.yaml        # Généré par generate-network.bash
├── network.env                # Généré par generate-network.bash
├── crypto-config.yaml         # Généré par generate-network.bash
├── configtx.yaml              # Généré par generate-network.bash
├── channel-artifacts/         # Généré par generate-network.bash (bloc de genèse, tx)
├── crypto-config/             # Généré par generate-network.bash (matériaux crypto)
├── template_chaincode/        # Exemple de chaincode en Go
│   ├── chaincode.go           # Implémentation du chaincode de thèse
│   ├── go.mod                 # Dépendances Go
│   ├── go.sum                 # Dépendances Go
│   └── main.go                # Point d'entrée
└── test/                      # Configurations de test
    └── testConf_1/            # Exemple de configuration préfaite
```

## 💡 Bonnes pratiques

1. **Isolation** : Lancez les scripts dans un dossier dédié pour éviter les conflits
2. **Chemins** : Adaptez les paths selon votre environnement si nécessaire
3. **Admins** : Chaque organisation devrait avoir au moins un admin spécifique (CLI)
4. **Sauvegarde** : Sauvegardez régulièrement le dossier `crypto-config/` contenant vos clés privées
5. **Monitoring** : Surveillez les logs des conteneurs avec `docker logs -f <nom_conteneur>`

## 🔧 Dépannage

- Si vous rencontrez des erreurs de TLS, vérifiez que les chemins vers les certificats sont corrects dans les variables d'environnement
- Pour les problèmes de connexion entre peers, assurez-vous que le réseau Docker `fabric` est actif
- En cas d'échec de déploiement de chaincode, vérifiez les logs du conteneur chaincode server
- Les chaincodes en mode CCaaS nécessitent que le port 9999 soit disponible sur l'hôte
