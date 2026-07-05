#!/bin/bash
set -e

ENV_FILE="network.env"
CONFIG_FILE="configtx.yaml"
CRYPTO_CONFIG_SPEC="crypto-config.yaml"
ARTIFACTS_DIR="./channel-artifacts"

# =================================================================
# 1. AUTOMATION : QUESTIONNAIRE INTERACTIF (SI NETWORK.ENV N'EXISTE PAS)
# =================================================================
if [ ! -f "$ENV_FILE" ]; then
    echo "================================================================="
    echo "   CONFIGURATION DYNAMIQUE MULTI-ORGANISATIONS ET MULTI-CANAUX   "
    echo "================================================================="
    echo "Le fichier $ENV_FILE est introuvable. Initialisation du questionnaire..."
    echo ""

    # Chemins d'accès et Orderer
    read -p "Chemin des binaires Fabric [./bin]: " INPUT_BIN
    INPUT_BIN=${INPUT_BIN:-"./bin"}
    read -p "Domaine de l'Orderer [example.com]: " INPUT_ORD_DOMAIN
    INPUT_ORD_DOMAIN=${INPUT_ORD_DOMAIN:-"example.com"}
    read -p "Chemin hôte du dossier crypto-config [./crypto-config]: " INPUT_CRYPTO_CONFIG
    INPUT_CRYPTO_CONFIG=${INPUT_CRYPTO_CONFIG:-"./crypto-config"}
    read -p "Chemin hôte du dossier channel-artifacts [./channel-artifacts]: " INPUT_CHANNEL_ARTIFACTS
    INPUT_CHANNEL_ARTIFACTS=${INPUT_CHANNEL_ARTIFACTS:-"./channel-artifacts"}
    read -p "Chemin hôte racine des données Peer [./peer-data]: " INPUT_PEER_DATA_ROOT
    INPUT_PEER_DATA_ROOT=${INPUT_PEER_DATA_ROOT:-"./peer-data"}

    # Nombre d'organisations
    while true; do
        read -p "Combien d'organisations de Peers voulez-vous créer ? (Min 1) [1]: " INPUT_NUM_ORGS
        INPUT_NUM_ORGS=${INPUT_NUM_ORGS:-1}
        [[ "$INPUT_NUM_ORGS" =~ ^[0-9]+$ ]] && [ "$INPUT_NUM_ORGS" -ge 1 ] && break
        echo "Nombre invalide."
    done

    # Écriture de la première partie du .env
    cat << EOF > $ENV_FILE
FABRIC_BIN_DIR="$INPUT_BIN"
ORDERER_DOMAIN="$INPUT_ORD_DOMAIN"
CRYPTO_CONFIG_DIR="$INPUT_CRYPTO_CONFIG"
CHANNEL_ARTIFACTS_DIR="$INPUT_CHANNEL_ARTIFACTS"
PEER_DATA_ROOT="$INPUT_PEER_DATA_ROOT"
NUM_ORGS=$INPUT_NUM_ORGS
CHANNEL_BATCH_TIMEOUT="2s"
CHANNEL_MAX_MESSAGE_COUNT=100
CHANNEL_ABSOLUTE_MAX_BYTES="99 MB"
CHANNEL_PREFERRED_MAX_BYTES="512 KB"
EOF

    # Collecte des Organisations
    for ((i=1; i<=INPUT_NUM_ORGS; i++)); do
        echo ""
        echo "--- Configuration de l'Organisation $i ---"
        read -p "Nom unique (ex: org1): " O_NAME
        read -p "ID du MSP (ex: org1MSP): " O_MSP
        read -p "Domaine (ex: org1.example.com): " O_DOMAIN
        read -p "Combien de peers pour cette organisation ? [1]: " O_PEERS
        O_PEERS=${O_PEERS:-1}

        cat << EOF >> $ENV_FILE
ORG${i}_NAME="$O_NAME"
ORG${i}_MSP="$O_MSP"
ORG${i}_DOMAIN="$O_DOMAIN"
ORG${i}_PEERS=$O_PEERS
EOF

        for ((p=0; p<${O_PEERS}; p++)); do
            echo ""
            echo "    --- Configuration du peer $p de ${O_NAME} ---"
            read -p "    Hostname/IP du peer $p (ex: peer${p}.${O_DOMAIN}): " PEER_HOST
            PEER_HOST=${PEER_HOST:-"peer${p}.${O_DOMAIN}"}
            read -p "    Port interne du peer $p [7051]: " PEER_PORT
            PEER_PORT=${PEER_PORT:-7051}
            read -p "    Port externe du peer $p [${PEER_PORT}]: " PEER_EXTERNAL_PORT
            PEER_EXTERNAL_PORT=${PEER_EXTERNAL_PORT:-$PEER_PORT}

            cat << PEER_EOF >> $ENV_FILE
ORG${i}_PEER${p}_HOST="$PEER_HOST"
ORG${i}_PEER${p}_PORT=$PEER_PORT
ORG${i}_PEER${p}_EXTERNAL_PORT=$PEER_EXTERNAL_PORT
PEER_EOF
        done

        # Demande oui/non UNE SEULE FOIS par organisation (norme Fabric : une seule
        # identité admin/CLI par org, jamais dupliquée sur chaque peer)
        echo ""
        while true; do
            read -p "    Voulez-vous générer un conteneur CLI admin pour l'organisation ${O_NAME} ? (o/n) [n]: " ORG_HAS_CLI
            ORG_HAS_CLI=${ORG_HAS_CLI:-n}
            case "$ORG_HAS_CLI" in
                [oOyY]) ORG_HAS_CLI="yes"; break ;;
                [nN]) ORG_HAS_CLI="no"; break ;;
                *) echo "    Réponse invalide, entrez 'o' ou 'n'." ;;
            esac
        done
        echo "ORG${i}_HAS_CLI=$ORG_HAS_CLI" >> $ENV_FILE
    done

    # Configuration dynamique des canaux
    echo ""
    echo "================================================================="
    while true; do
        read -p "Combien de canaux applicatifs voulez-vous créer ? (Min 1) [1]: " INPUT_NUM_CHANNELS
        INPUT_NUM_CHANNELS=${INPUT_NUM_CHANNELS:-1}
        [[ "$INPUT_NUM_CHANNELS" =~ ^[0-9]+$ ]] && [ "$INPUT_NUM_CHANNELS" -ge 1 ] && break
        echo "Nombre invalide."
    done
    
    echo "NUM_CHANNELS=$INPUT_NUM_CHANNELS" >> $ENV_FILE

    for ((c=1; c<=INPUT_NUM_CHANNELS; c++)); do
        echo ""
        echo "--- Configuration du Canal $c ---"
        read -p "Nom réel du canal (minuscules uniquement, ex: canaltest): " CH_NAME
        echo "CH${c}_NAME=\"$CH_NAME\"" >> $ENV_FILE
        
        echo "Quelles organisations participent à ce canal ? (Entrez les numéros séparés par des espaces, ex: 1 2)"
        echo "Organisations disponibles :"
        for ((i=1; i<=INPUT_NUM_ORGS; i++)); do
            NAME_VAR="ORG${i}_NAME"
            echo "  [$i] ${!NAME_VAR}"
        done
        read -p "Votre choix : " CH_ORGS
        echo "CH${c}_ORGS=\"$CH_ORGS\"" >> $ENV_FILE
    done

    echo ""
    echo "✅ Fichier '$ENV_FILE' enregistré avec succès !"
    echo "================================================================="
fi

# Chargement des variables pour la suite du script
source $ENV_FILE
export PATH=$(realpath "${FABRIC_BIN_DIR}"):$PATH

# =================================================================
# 2. AUTOMATION : GÉNÉRATION DE CRYPTO-CONFIG.YAML ET DES CLÉS
# =================================================================
if [ ! -d "crypto-config" ]; then
    echo "==> Génération automatique de $CRYPTO_CONFIG_SPEC..."
    
    cat << EOF > $CRYPTO_CONFIG_SPEC
OrdererOrgs:
  - Name: Orderer
    Domain: ${ORDERER_DOMAIN}
    Specs:
      - Hostname: orderer
PeerOrgs:
EOF

    for ((i=1; i<=NUM_ORGS; i++)); do
        NAME_VAR="ORG${i}_NAME"
        DOMAIN_VAR="ORG${i}_DOMAIN"
        PEERS_VAR="ORG${i}_PEERS"

        cat << EOF >> $CRYPTO_CONFIG_SPEC
  - Name: ${!NAME_VAR}
    Domain: ${!DOMAIN_VAR}
    EnableNodeOUs: true
    Specs:
EOF
        # Un Spec par peer réel (peer0, peer1, ...) ET un hostname fictif cc-peer<i>
        # dédié uniquement à fournir un certificat TLS indépendant pour le conteneur
        # serveur du chaincode (CCaaS) associé à ce peer.
        for ((p=0; p<${!PEERS_VAR}; p++)); do
            cat << EOF >> $CRYPTO_CONFIG_SPEC
      - Hostname: peer${p}
      - Hostname: cc-peer${p}
EOF
        done

        cat << EOF >> $CRYPTO_CONFIG_SPEC
    Users:
      Count: 1
EOF
    done

    echo "==> Exécution de cryptogen generate..."
    cryptogen generate --config=./$CRYPTO_CONFIG_SPEC
fi

# =================================================================
# GENERATION DOCKER-COMPOSE (AVEC CHEMINS RELATIFS DYNAMIQUES)
# =================================================================

DOCKER_FILE="docker-compose.yaml"
echo "==> Génération docker-compose avec chemins dynamiques..."

# Générer le docker-compose.yaml
cat <<EOF > $DOCKER_FILE
version: "3.8"

networks:
  fabric:
    name: fabric

services:
EOF

# Générer les peers
for ((i=1;i<=NUM_ORGS;i++)); do
  NAME_VAR="ORG${i}_NAME"
  DOMAIN_VAR="ORG${i}_DOMAIN"
  PEERS_VAR="ORG${i}_PEERS"
  MSP_VAR="ORG${i}_MSP"

  for ((p=0;p<${!PEERS_VAR};p++)); do
    PEER_HOST_VAR="ORG${i}_PEER${p}_HOST"
    PEER_PORT_VAR="ORG${i}_PEER${p}_PORT"
    PEER_EXTERNAL_PORT_VAR="ORG${i}_PEER${p}_EXTERNAL_PORT"

    cat <<EOF >> $DOCKER_FILE
  peer${p}.${!DOMAIN_VAR}:
    image: hyperledger/fabric-peer:2.5
    container_name: peer${p}.${!DOMAIN_VAR}
    working_dir: /opt/gopath/src/github.com/hyperledger/fabric/peer
    environment:
      CORE_VM_ENDPOINT: unix:///host/var/run/docker.sock
      CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE: fabric
      CORE_PEER_ID: peer${p}.${!DOMAIN_VAR}
      CORE_PEER_ADDRESS: ${!PEER_HOST_VAR}:${!PEER_PORT_VAR}
      CORE_PEER_LISTENADDRESS: 0.0.0.0:${!PEER_PORT_VAR}
      CORE_PEER_CHAINCODEADDRESS: ${!PEER_HOST_VAR}:7052
      CORE_PEER_CHAINCODELISTENADDRESS: 0.0.0.0:7052
      CORE_PEER_LOCALMSPID: ${!MSP_VAR}
      CORE_PEER_MSPCONFIGPATH: /etc/hyperledger/fabric/msp
      CORE_PEER_TLS_ENABLED: true
      CORE_PEER_TLS_CERT_FILE: /etc/hyperledger/fabric/tls/server.crt
      CORE_PEER_TLS_KEY_FILE: /etc/hyperledger/fabric/tls/server.key
      CORE_PEER_TLS_ROOTCERT_FILE: /etc/hyperledger/fabric/tls/ca.crt
      ORDERER_CA: /etc/hyperledger/orderer/tls/ca.crt
      FABRIC_CFG_PATH: /etc/hyperledger/fabric
      CORE_PEER_GOSSIP_BOOTSTRAP: peer0.${!DOMAIN_VAR}:${!PEER_PORT_VAR}
      CORE_PEER_GOSSIP_EXTERNALENDPOINT: ${!PEER_HOST_VAR}:${!PEER_PORT_VAR}
      CORE_PEER_GOSSIP_USELEADERELECTION: "true"
      CORE_PEER_GOSSIP_ORGLEADER: "false"
      CORE_LEDGER_STATE_STATEDATABASE: goleveldb
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock
      - ${CRYPTO_CONFIG_DIR}/peerOrganizations/${!DOMAIN_VAR}/peers/peer${p}.${!DOMAIN_VAR}/msp:/etc/hyperledger/fabric/msp:ro
      - ${CRYPTO_CONFIG_DIR}/peerOrganizations/${!DOMAIN_VAR}/peers/peer${p}.${!DOMAIN_VAR}/tls:/etc/hyperledger/fabric/tls:ro
      - ${CRYPTO_CONFIG_DIR}/ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}/tls:/etc/hyperledger/orderer/tls:ro
      - ${CHANNEL_ARTIFACTS_DIR}:/var/hyperledger/orderer/channel-artifacts
      - ${PEER_DATA_ROOT}/peer${p}.${!DOMAIN_VAR}:/var/hyperledger/production
    ports:
      - "${!PEER_EXTERNAL_PORT_VAR}:${!PEER_PORT_VAR}"
    networks:
      - fabric
    depends_on:
      - orderer.${ORDERER_DOMAIN}

EOF
  done
done

# Générer un conteneur CLI admin par organisation l'ayant demandé
# (norme Fabric : une seule identité admin par org, centralisée dans le CLI,
# jamais dupliquée sur les peers individuels)
for ((i=1;i<=NUM_ORGS;i++)); do
  NAME_VAR="ORG${i}_NAME"
  MSP_VAR="ORG${i}_MSP"
  DOMAIN_VAR="ORG${i}_DOMAIN"
  HAS_CLI_VAR="ORG${i}_HAS_CLI"
  PEER0_HOST_VAR="ORG${i}_PEER0_HOST"
  PEER0_PORT_VAR="ORG${i}_PEER0_PORT"

  if [ "${!HAS_CLI_VAR}" == "yes" ]; then
    cat <<EOF >> $DOCKER_FILE
  cli.${!DOMAIN_VAR}:
    image: hyperledger/fabric-tools:2.5
    container_name: cli.${!DOMAIN_VAR}
    tty: true
    stdin_open: true
    working_dir: /opt/gopath/src/github.com/hyperledger/fabric/peer
    environment:
      GOPATH: /opt/gopath
      CORE_VM_ENDPOINT: unix:///host/var/run/docker.sock
      CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE: fabric
      FABRIC_LOGGING_SPEC: INFO
      CORE_PEER_TLS_ENABLED: true
      CORE_PEER_LOCALMSPID: ${!MSP_VAR}
      CORE_PEER_TLS_ROOTCERT_FILE: /etc/hyperledger/fabric/tls/ca.crt
      CORE_PEER_MSPCONFIGPATH: /etc/hyperledger/fabric/admin-msp
      CORE_PEER_ADDRESS: ${!PEER0_HOST_VAR}:${!PEER0_PORT_VAR}
      ORDERER_CA: /etc/hyperledger/orderer/tls/ca.crt
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock
      - ${CRYPTO_CONFIG_DIR}/peerOrganizations/${!DOMAIN_VAR}/users/Admin@${!DOMAIN_VAR}/msp:/etc/hyperledger/fabric/admin-msp:ro
      - ${CRYPTO_CONFIG_DIR}/peerOrganizations/${!DOMAIN_VAR}/peers/peer0.${!DOMAIN_VAR}/tls:/etc/hyperledger/fabric/tls:ro
      - ${CRYPTO_CONFIG_DIR}/ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}/tls:/etc/hyperledger/orderer/tls:ro
      - ${CHANNEL_ARTIFACTS_DIR}:/var/hyperledger/orderer/channel-artifacts
      - ${CRYPTO_CONFIG_DIR}:/etc/hyperledger/fabric/crypto-config:ro
    networks:
      - fabric
    depends_on:
      - orderer.${ORDERER_DOMAIN}
      - peer0.${!DOMAIN_VAR}

EOF
  fi
done
cat <<EOF >> $DOCKER_FILE
  orderer.${ORDERER_DOMAIN}:
    image: hyperledger/fabric-orderer:2.5
    container_name: orderer.${ORDERER_DOMAIN}
    working_dir: /opt/gopath/src/github.com/hyperledger/fabric/orderer
    environment:
      ORDERER_GENERAL_LISTENADDRESS: 0.0.0.0
      ORDERER_GENERAL_LISTENPORT: 7050
      ORDERER_GENERAL_LOCALMSPID: OrdererMSP
      ORDERER_GENERAL_LOCALMSPDIR: /var/hyperledger/orderer/msp
      ORDERER_GENERAL_TLS_ENABLED: true
      ORDERER_ADMIN_LISTENADDRESS: 0.0.0.0:7053
      ORDERER_ADMIN_TLS_ENABLED: true
      ORDERER_ADMIN_TLS_PRIVATEKEY: /var/hyperledger/orderer/tls/server.key
      ORDERER_ADMIN_TLS_CERTIFICATE: /var/hyperledger/orderer/tls/server.crt
      ORDERER_ADMIN_TLS_ROOTCAS: '[/var/hyperledger/orderer/tls/ca.crt]'
      ORDERER_ADMIN_TLS_CLIENTAUTHREQUIRED: true
      ORDERER_ADMIN_TLS_CLIENTROOTCAS: '[/var/hyperledger/orderer/tls/ca.crt]'
      ORDERER_GENERAL_TLS_PRIVATEKEY: /var/hyperledger/orderer/tls/server.key
      ORDERER_GENERAL_TLS_CERTIFICATE: /var/hyperledger/orderer/tls/server.crt
      ORDERER_GENERAL_TLS_ROOTCAS: '[/var/hyperledger/orderer/tls/ca.crt]'
      ORDERER_GENERAL_BOOTSTRAPMETHOD: none
      ORDERER_CHANNELPARTICIPATION_ENABLED: true
    volumes:
      - ${CRYPTO_CONFIG_DIR}/ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}/msp:/var/hyperledger/orderer/msp:ro
      - ${CRYPTO_CONFIG_DIR}/ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}/tls:/var/hyperledger/orderer/tls:ro
      - ${CHANNEL_ARTIFACTS_DIR}:/var/hyperledger/orderer/channel-artifacts
      - orderer.${ORDERER_DOMAIN}:/var/hyperledger/production/orderer
    ports:
      - "7050:7050"
      - "7053:7053"
    networks:
      - fabric

volumes:
EOF

# Ajouter les volumes pour les peers
for ((i=1;i<=NUM_ORGS;i++)); do
  DOMAIN_VAR="ORG${i}_DOMAIN"
  PEERS_VAR="ORG${i}_PEERS"
  
  for ((p=0;p<${!PEERS_VAR};p++)); do
    echo "  peer${p}.${!DOMAIN_VAR}:" >> $DOCKER_FILE
  done
done

# Ajouter le volume pour l'orderer
echo "  orderer.${ORDERER_DOMAIN}:" >> $DOCKER_FILE

echo ""
echo "✓ docker-compose.yaml généré avec chemins relatifs portables"


# =================================================================
# 3. GÉNÉRATION DU CONFIGTX.YAML DYNAMIQUE (POLICIES AU PLURIEL)
# =================================================================
echo "==> Génération de $CONFIG_FILE..."
echo "" > $CONFIG_FILE

cat << EOF >> $CONFIG_FILE
Organizations:
    - &OrdererOrg
        Name: OrdererOrg
        ID: OrdererMSP
        MSPDir: crypto-config/ordererOrganizations/${ORDERER_DOMAIN}/msp
        Policies:
            Readers: {Type: Signature, Rule: "OR('OrdererMSP.member')"}
            Writers: {Type: Signature, Rule: "OR('OrdererMSP.member')"}
            Admins:  {Type: Signature, Rule: "OR('OrdererMSP.admin')"}
            
EOF

for ((i=1; i<=NUM_ORGS; i++)); do
    NAME_VAR="ORG${i}_NAME"
    MSP_VAR="ORG${i}_MSP"
    DOMAIN_VAR="ORG${i}_DOMAIN"

cat << EOF >> $CONFIG_FILE
    - &${!NAME_VAR}
        Name: ${!NAME_VAR}
        ID: ${!MSP_VAR}
        MSPDir: crypto-config/peerOrganizations/${!DOMAIN_VAR}/msp
        Policies:
            Readers:     {Type: Signature, Rule: "OR('${!MSP_VAR}.admin', '${!MSP_VAR}.peer', '${!MSP_VAR}.client')"}
            Writers:     {Type: Signature, Rule: "OR('${!MSP_VAR}.admin', '${!MSP_VAR}.client')"}
            Admins:      {Type: Signature, Rule: "OR('${!MSP_VAR}.admin')"}
            Endorsement: {Type: Signature, Rule: "OR('${!MSP_VAR}.peer')"}
        AnchorPeers:
            - Host: peer0.${!DOMAIN_VAR}
              Port: 7051
EOF
done

cat << EOF >> $CONFIG_FILE

Capabilities:
    Channel: &ChannelCapabilities
        V2_0: true
    Orderer: &OrdererCapabilities
        V2_0: true
    Application: &ApplicationCapabilities
        V2_0: true

Channel: &ChannelDefaults
    Policies:
        Readers: {Type: ImplicitMeta, Rule: "ANY Readers"}
        Writers: {Type: ImplicitMeta, Rule: "ANY Writers"}
        Admins:  {Type: ImplicitMeta, Rule: "MAJORITY Admins"}

Application: &ApplicationDefaults
    Organizations:
    Policies:
        LifecycleEndorsement: {Type: ImplicitMeta, Rule: "MAJORITY Endorsement"}
        Endorsement:          {Type: ImplicitMeta, Rule: "MAJORITY Endorsement"}
        Readers:              {Type: ImplicitMeta, Rule: "ANY Readers"}
        Writers:              {Type: ImplicitMeta, Rule: "ANY Writers"}
        Admins:               {Type: ImplicitMeta, Rule: "MAJORITY Admins"}
    Capabilities:
        <<: *ApplicationCapabilities

Orderer: &OrdererDefaults
    OrdererType: etcdraft
    Addresses:
        - orderer.${ORDERER_DOMAIN}:7050
    BatchTimeout: ${CHANNEL_BATCH_TIMEOUT}
    BatchSize:
        MaxMessageCount: ${CHANNEL_MAX_MESSAGE_COUNT}
        AbsoluteMaxBytes: ${CHANNEL_ABSOLUTE_MAX_BYTES}
        PreferredMaxBytes: ${CHANNEL_PREFERRED_MAX_BYTES}
    Organizations:
    Policies:
        Readers:         {Type: ImplicitMeta, Rule: "ANY Readers"}
        Writers:         {Type: ImplicitMeta, Rule: "ANY Writers"}
        Admins:          {Type: ImplicitMeta, Rule: "MAJORITY Admins"}
        BlockValidation: {Type: ImplicitMeta, Rule: "ANY Writers"}
EOF

echo "" >> $CONFIG_FILE
echo "Profiles:" >> $CONFIG_FILE
echo "    MultiOrgsOrdererGenesis:" >> $CONFIG_FILE
echo "        <<: *ChannelDefaults" >> $CONFIG_FILE
echo "        Capabilities: *ChannelCapabilities" >> $CONFIG_FILE
echo "        Orderer:" >> $CONFIG_FILE
echo "            <<: *OrdererDefaults" >> $CONFIG_FILE
echo "            EtcdRaft:" >> $CONFIG_FILE
echo "                Consenters:" >> $CONFIG_FILE
echo "                    - Host: orderer.${ORDERER_DOMAIN}" >> $CONFIG_FILE
echo "                      Port: 7050" >> $CONFIG_FILE
echo "                      ClientTLSCert: crypto-config/ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}/tls/server.crt" >> $CONFIG_FILE
echo "                      ServerTLSCert: crypto-config/ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}/tls/server.crt" >> $CONFIG_FILE
echo "            Organizations: [*OrdererOrg]" >> $CONFIG_FILE
echo "            Capabilities: *OrdererCapabilities" >> $CONFIG_FILE
echo "        Consortiums:" >> $CONFIG_FILE
echo "            SampleConsortium:" >> $CONFIG_FILE
echo "                Organizations:" >> $CONFIG_FILE
for ((i=1; i<=NUM_ORGS; i++)); do
    NAME_VAR="ORG${i}_NAME"
    echo "                    - *${!NAME_VAR}" >> $CONFIG_FILE
done

for ((c=1; c<=NUM_CHANNELS; c++)); do
    CH_NAME_VAR="CH${c}_NAME"
    CH_ORGS_VAR="CH${c}_ORGS"
    
    echo "    Profile_${!CH_NAME_VAR}:" >> $CONFIG_FILE
    echo "        <<: *ChannelDefaults" >> $CONFIG_FILE
    echo "        Capabilities: *ChannelCapabilities" >> $CONFIG_FILE
    echo "        Orderer:" >> $CONFIG_FILE
    echo "            <<: *OrdererDefaults" >> $CONFIG_FILE
    echo "            EtcdRaft:" >> $CONFIG_FILE
    echo "                Consenters:" >> $CONFIG_FILE
    echo "                    - Host: orderer.${ORDERER_DOMAIN}" >> $CONFIG_FILE
    echo "                      Port: 7050" >> $CONFIG_FILE
    echo "                      ClientTLSCert: crypto-config/ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}/tls/server.crt" >> $CONFIG_FILE
    echo "                      ServerTLSCert: crypto-config/ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}/tls/server.crt" >> $CONFIG_FILE
    echo "            Organizations: [*OrdererOrg]" >> $CONFIG_FILE
    echo "            Capabilities: *OrdererCapabilities" >> $CONFIG_FILE
    echo "        Application:" >> $CONFIG_FILE
    echo "            <<: *ApplicationDefaults" >> $CONFIG_FILE
    echo "            Organizations:" >> $CONFIG_FILE
    
    for org_idx in ${!CH_ORGS_VAR}; do
        NAME_VAR="ORG${org_idx}_NAME"
        echo "                - *${!NAME_VAR}" >> $CONFIG_FILE
    done
    echo "            Capabilities: *ApplicationCapabilities" >> $CONFIG_FILE
done

# =================================================================
# 4. COMPILATION VIA CONFIGTXGEN
# =================================================================
echo ""
echo "==> Préparation de la compilation..."

export FABRIC_CFG_PATH=${PWD}
mkdir -p $ARTIFACTS_DIR

if [ ! -d "crypto-config" ]; then
    echo "❌ Erreur critique : le dossier 'crypto-config/' est manquant. Vérifiez que cryptogen s'est exécuté correctement."
    exit 1
fi

echo "==> Compilation des fichiers binaires..."

# Génération des blocs de genèse des canaux applicatifs (Fabric 2.5 / channel participation)
# Note: en Fabric 2.5 avec bootstrapmethod=none, il n'y a plus de system channel.
# Chaque canal est rejoint via 'osnadmin channel join --channelID <id> --config-block <block>'
# après le démarrage de l'orderer. Le bloc de genèse est généré ici pour chaque canal.
for ((c=1; c<=NUM_CHANNELS; c++)); do
    CH_NAME_VAR="CH${c}_NAME"
    CH_ORGS_VAR="CH${c}_ORGS"

    echo "-> Génération du bloc de genèse du canal : ${!CH_NAME_VAR}..."
    configtxgen -profile Profile_${!CH_NAME_VAR} \
        -outputBlock ${ARTIFACTS_DIR}/${!CH_NAME_VAR}_genesis.block \
        -channelID ${!CH_NAME_VAR}

    echo "   ✓ Bloc de genèse : ${ARTIFACTS_DIR}/${!CH_NAME_VAR}_genesis.block"
    echo ""
    echo "   ℹ️  Pour rejoindre ce canal après 'docker-compose up -d', exécutez :"
    echo "      osnadmin channel join --channelID ${!CH_NAME_VAR} \\"
    echo "        --config-block ${ARTIFACTS_DIR}/${!CH_NAME_VAR}_genesis.block \\"
    echo "        -o localhost:7053 --ca-file <orderer-tls-ca> \\"
    echo "        --client-cert <admin-tls-cert> --client-key <admin-tls-key>"
    echo ""
    echo "   ℹ️  Pour mettre à jour les Anchor Peers en Fabric 2.5 (via config update) :"
    for org_idx in ${!CH_ORGS_VAR}; do
        NAME_VAR="ORG${org_idx}_NAME"
        MSP_VAR="ORG${org_idx}_MSP"
        DOMAIN_VAR="ORG${org_idx}_DOMAIN"
        echo "      # ${!NAME_VAR} : peer channel fetch config, puis jq pour injecter l'anchor peer,"
        echo "      # puis peer channel update --orderer ... (voir docs Fabric 2.5)"
    done
done

echo ""
echo "✅ Tout est généré avec succès dans le dossier '${ARTIFACTS_DIR}' !"
echo ""
echo "Prochaines étapes (Fabric 2.5 — channel participation API) :"
echo "  1. docker-compose up -d"
echo "  2. Pour chaque canal, rejoindre l'orderer :"
echo "       osnadmin channel join --channelID <canal> \\"
echo "         --config-block ${ARTIFACTS_DIR}/<canal>_genesis.block \\"
echo "         -o localhost:7053 --ca-file <orderer-tls-ca> \\"
echo "         --client-cert <admin-tls-cert> --client-key <admin-tls-key>"
echo "  3. Pour chaque peer, rejoindre le canal :"
echo "       peer channel join -b ${ARTIFACTS_DIR}/<canal>_genesis.block"
echo "  4. Déployer les chaincodes :"
echo "       ./chaincode-config.sh"