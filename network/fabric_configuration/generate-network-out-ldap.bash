#!/bin/bash
set -e

# =================================================================
#  GÉNÉRATION D'UN RÉSEAU HYPERLEDGER FABRIC BASÉ SUR FABRIC-CA
#  (Fabric-CA + PostgreSQL + OpenLDAP par organisation, conteneurisé)
#
#  Ce script ne s'occupe QUE du réseau :
#   - 1 serveur Fabric-CA par organisation (+ 1 pour l'Orderer)
#   - Chaque CA persiste ses identités/certificats dans PostgreSQL
#   - Chaque organisation a un conteneur OpenLDAP prêt à recevoir un
#     bootstrap LDIF (structure/groupes/utilisateurs)
#   - docker-compose.yaml, configtx.yaml (généralisé pour N organisations)
#
#  La génération des groupes et utilisateurs LDAP (LDIF, mots de passe
#  hashés SSHA) est désormais un sujet séparé : voir
#  ./generate-ldap-identities.sh, qui lit configtx.yaml après coup et
#  écrit directement dans ${FABRIC_CA_DIR}/<org>/ldap-bootstrap/.
#  Ce script-ci se contente de créer le dossier vide (monté par
#  docker-compose) : rien n'y est pré-rempli ici.
# =================================================================

ENV_FILE="network.env"
CONFIG_FILE="configtx.yaml"
ARTIFACTS_DIR="./channel-artifacts"
ORG_ROOT_DIR="./organizations"
FABRIC_CA_DIR="./fabric-ca"

# =================================================================
# 1. AUTOMATION : QUESTIONNAIRE INTERACTIF (SI NETWORK.ENV N'EXISTE PAS)
# =================================================================
if [ ! -f "$ENV_FILE" ]; then
    echo "================================================================="
    echo "   CONFIGURATION DYNAMIQUE MULTI-ORGANISATIONS ET MULTI-CANAUX   "
    echo "   (PKI basée sur Fabric-CA + PostgreSQL + OpenLDAP)             "
    echo "================================================================="
    echo "Le fichier $ENV_FILE est introuvable. Initialisation du questionnaire..."
    echo ""

    read -p "Chemin des binaires Fabric (configtxgen...) [./bin]: " INPUT_BIN
    INPUT_BIN=${INPUT_BIN:-"./bin"}
    read -p "Domaine de l'Orderer [example.com]: " INPUT_ORD_DOMAIN
    INPUT_ORD_DOMAIN=${INPUT_ORD_DOMAIN:-"example.com"}
    read -p "Chemin hôte du dossier channel-artifacts [./channel-artifacts]: " INPUT_CHANNEL_ARTIFACTS
    INPUT_CHANNEL_ARTIFACTS=${INPUT_CHANNEL_ARTIFACTS:-"./channel-artifacts"}
    read -p "Chemin hôte racine des données Peer [./peer-data]: " INPUT_PEER_DATA_ROOT
    INPUT_PEER_DATA_ROOT=${INPUT_PEER_DATA_ROOT:-"./peer-data"}
    read -p "Mot de passe admin bootstrap commun à toutes les CA [adminpw]: " INPUT_CA_ADMIN_PASS
    INPUT_CA_ADMIN_PASS=${INPUT_CA_ADMIN_PASS:-"adminpw"}

    while true; do
        read -p "Combien d'organisations de Peers voulez-vous créer ? (Min 1) [1]: " INPUT_NUM_ORGS
        INPUT_NUM_ORGS=${INPUT_NUM_ORGS:-1}
        [[ "$INPUT_NUM_ORGS" =~ ^[0-9]+$ ]] && [ "$INPUT_NUM_ORGS" -ge 1 ] && break
        echo "Nombre invalide."
    done

    cat << EOF > $ENV_FILE
FABRIC_BIN_DIR="$INPUT_BIN"
ORDERER_DOMAIN="$INPUT_ORD_DOMAIN"
ORG_ROOT_DIR="$ORG_ROOT_DIR"
CHANNEL_ARTIFACTS_DIR="$INPUT_CHANNEL_ARTIFACTS"
PEER_DATA_ROOT="$INPUT_PEER_DATA_ROOT"
NUM_ORGS=$INPUT_NUM_ORGS
CHANNEL_BATCH_TIMEOUT="2s"
CHANNEL_MAX_MESSAGE_COUNT=100
CHANNEL_ABSOLUTE_MAX_BYTES="99 MB"
CHANNEL_PREFERRED_MAX_BYTES="512 KB"
CA_ADMIN_USER="admin"
CA_ADMIN_PASS="$INPUT_CA_ADMIN_PASS"

# --- CA / DB / LDAP de l'Orderer ---
ORDERER_CA_PORT=7054
ORDERER_CA_OPERATIONS_PORT=17054
ORDERER_DB_PORT=5432
ORDERER_DB_NAME="fabric_ca_orderer"
ORDERER_DB_USER="fabricca"
ORDERER_DB_PASS="fabriccapw"
ORDERER_LDAP_PORT=1389
ORDERER_LDAP_ADMIN_PASS="ldapadminpw"
EOF

    for ((i=1; i<=INPUT_NUM_ORGS; i++)); do
        echo ""
        echo "--- Configuration de l'Organisation $i ---"
        read -p "Nom unique (ex: org1): " O_NAME
        read -p "ID du MSP (ex: org1MSP): " O_MSP
        read -p "Domaine (ex: org1.example.com): " O_DOMAIN
        read -p "Combien de peers pour cette organisation ? [1]: " O_PEERS
        O_PEERS=${O_PEERS:-1}
        declare "ORG${i}_NAME=$O_NAME"

        CA_PORT=$((7054 + i*1000))
        OP_PORT=$((17054 + i*1000))
        DB_PORT=$((5432 + i))
        LDAP_PORT=$((1389 + i))

        cat << EOF >> $ENV_FILE
ORG${i}_NAME="$O_NAME"
ORG${i}_MSP="$O_MSP"
ORG${i}_DOMAIN="$O_DOMAIN"
ORG${i}_PEERS=$O_PEERS
ORG${i}_CA_PORT=$CA_PORT
ORG${i}_CA_OPERATIONS_PORT=$OP_PORT
ORG${i}_DB_PORT=$DB_PORT
ORG${i}_DB_NAME="fabric_ca_${O_NAME}"
ORG${i}_DB_USER="fabricca"
ORG${i}_DB_PASS="fabriccapw"
ORG${i}_LDAP_PORT=$LDAP_PORT
ORG${i}_LDAP_ADMIN_PASS="ldapadminpw"
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
# 2. GÉNÉRATION DES CONFIGS FABRIC-CA (PAR ORGANISATION)
#    -> Ne génère plus aucun LDIF. Uniquement fabric-ca-server-config.yaml
#       et le dossier vide ldap-bootstrap/ (rempli plus tard par
#       generate-ldap-identities.sh).
# =================================================================
# $1 = nom court (ex: org1, orderer)
# $2 = nom d'affichage / O= du certificat (ex: Org1, Orderer)
# $3 = port CA
# $4 = port operations CA
# $5 = nom DB
# $6 = utilisateur DB
# $7 = mot de passe DB
# $8 = mot de passe admin LDAP (utilisé uniquement dans le bloc commenté
#      ci-dessous, si vous activez un jour LDAP comme registry de la CA)
# $9 = base DN LDAP (idem)
generate_ca_config() {
    local SHORTNAME="$1"
    local DISPLAYNAME="$2"
    local CA_PORT="$3"
    local OP_PORT="$4"
    local DB_HOST="postgres.${SHORTNAME}"
    local DB_NAME="$5"
    local DB_USER="$6"
    local DB_PASS="$7"
    local LDAP_ADMIN_PASS="$8"
    local LDAP_BASE_DN="$9"

    local CA_DIR="${FABRIC_CA_DIR}/${SHORTNAME}"
    local LDAP_DIR="${FABRIC_CA_DIR}/${SHORTNAME}/ldap-bootstrap"
    mkdir -p "$CA_DIR" "$LDAP_DIR"

    cat << EOF > "${CA_DIR}/fabric-ca-server-config.yaml"
version: 1.5.13
port: ${CA_PORT}
debug: false
crlsizelimit: 512000

tls:
  enabled: false

ca:
  name: ca-${SHORTNAME}

crl:
  expiry: 24h

registry:
  maxenrollments: -1
  identities:
    - name: ${CA_ADMIN_USER}
      pass: ${CA_ADMIN_PASS}
      type: client
      affiliation: ""
      attrs:
        hf.Registrar.Roles: "*"
        hf.Registrar.DelegateRoles: "*"
        hf.Revoker: true
        hf.IntermediateCA: true
        hf.GenCRL: true
        hf.Registrar.Attributes: "*"
        hf.AffiliationMgr: true

db:
  type: postgres
  datasource: "host=${DB_HOST} port=5432 user=${DB_USER} password=${DB_PASS} dbname=${DB_NAME} sslmode=disable"
  tls:
    enabled: false

# --------------------------------------------------------------------
# Intégration LDAP (annuaire visible dans le schéma d'architecture)
# --------------------------------------------------------------------
# Désactivée par défaut : PostgreSQL reste le "registry" faisant autorité
# pour le register/enroll de Fabric-CA (c'est ce qui garantit que le type
# d'identité - peer/orderer/admin/client - est correctement gravé dans le
# certificat pour les NodeOUs). Un annuaire LDAP est démarré séparément et
# rempli par ./generate-ldap-identities.sh (groupes RBAC applicatifs +
# utilisateurs), pour un usage applicatif (SSO, lookup d'identité,
# contrôles d'accès dans vhsmd), conformément au schéma d'architecture
# Fabric-CA fourni.
#
# Pour faire de LDAP le registre d'authentification de la CA elle-même
# (comme le permet Fabric-CA nativement), décommentez le bloc ci-dessous.
# Attention : dans ce mode, "register" n'est plus utilisé (les identités
# doivent déjà exister dans LDAP) et vous perdez l'auto-provisioning du
# "type" d'identité utilisé par NodeOUs sans configuration additionnelle
# des "converters" LDAP -> attributs Fabric-CA (hf.*).
#
# ldap:
#   enabled: true
#   url: ldap://cn=admin,${LDAP_BASE_DN}:${LDAP_ADMIN_PASS}@ldap.${SHORTNAME}:389/${LDAP_BASE_DN}
#   userfilter: (uid=%s)
#   attribute:
#     names: ['uid','businessCategory']
#     converters:
#       - name: hf.Registrar.Roles
#         value: attr("businessCategory")

affiliations:
  ${SHORTNAME}:
    - department1
    - department2

signing:
  default:
    usage:
      - digital signature
    expiry: 8760h
  profiles:
    ca:
      usage:
        - cert sign
        - crl sign
      caconstraint:
        isca: true
        maxpathlen: 0
      expiry: 43800h
    tls:
      usage:
        - signing
        - key encipherment
        - server auth
        - client auth
        - key agreement
      expiry: 8760h

csr:
  cn: ca-${SHORTNAME}
  keyrequest:
    algo: ecdsa
    size: 256
  names:
    - C: FR
      ST: "N/A"
      L: "N/A"
      O: ${DISPLAYNAME}
      OU: Fabric-CA
  hosts:
    - ca.${SHORTNAME}
    - localhost
  ca:
    expiry: 131400h
    pathlength: 1

operations:
  listenAddress: 0.0.0.0:${OP_PORT}
  tls:
    enabled: false
EOF
}

# Convertit un domaine (org1.example.com) en base DN LDAP (dc=org1,dc=example,dc=com)
domain_to_dn() {
    local DOMAIN="$1"
    echo "dc=$(echo "$DOMAIN" | sed 's/\./,dc=/g')"
}

echo "==> Génération des configurations Fabric-CA..."

# --- CA de l'Orderer ---
ORDERER_LDAP_DN=$(domain_to_dn "$ORDERER_DOMAIN")
generate_ca_config "orderer" "OrdererOrg" "$ORDERER_CA_PORT" "$ORDERER_CA_OPERATIONS_PORT" \
    "$ORDERER_DB_NAME" "$ORDERER_DB_USER" "$ORDERER_DB_PASS" \
    "$ORDERER_LDAP_ADMIN_PASS" "$ORDERER_LDAP_DN"

# --- CA de chaque organisation ---
for ((i=1; i<=NUM_ORGS; i++)); do
    NAME_VAR="ORG${i}_NAME"; DISPLAYNAME="${!NAME_VAR}"
    DOMAIN_VAR="ORG${i}_DOMAIN"
    CA_PORT_VAR="ORG${i}_CA_PORT"
    OP_PORT_VAR="ORG${i}_CA_OPERATIONS_PORT"
    DB_NAME_VAR="ORG${i}_DB_NAME"; DB_USER_VAR="ORG${i}_DB_USER"; DB_PASS_VAR="ORG${i}_DB_PASS"
    LDAP_PASS_VAR="ORG${i}_LDAP_ADMIN_PASS"

    ORG_LDAP_DN=$(domain_to_dn "${!DOMAIN_VAR}")

    generate_ca_config "${!NAME_VAR}" "${!NAME_VAR}" "${!CA_PORT_VAR}" "${!OP_PORT_VAR}" \
        "${!DB_NAME_VAR}" "${!DB_USER_VAR}" "${!DB_PASS_VAR}" \
        "${!LDAP_PASS_VAR}" "$ORG_LDAP_DN"
done

echo "   ✓ Fichiers écrits dans ${FABRIC_CA_DIR}/<org>/ (config CA + dossier ldap-bootstrap/ vide)"

# =================================================================
# 3. GÉNÉRATION DOCKER-COMPOSE (CA + POSTGRES + LDAP + PEERS + ORDERER)
# =================================================================
DOCKER_FILE="docker-compose.yaml"
echo "==> Génération de ${DOCKER_FILE}..."

cat <<EOF > $DOCKER_FILE
version: "3.8"

networks:
  fabric:
    name: fabric

services:
EOF

# ---- Bloc réutilisable : postgres + ldap + ca pour une organisation ----
append_ca_stack() {
    local SHORTNAME="$1"        # ex: org1 / orderer
    local CA_PORT="$2"
    local OP_PORT="$3"
    local DB_PORT="$4"
    local DB_NAME="$5"
    local DB_USER="$6"
    local DB_PASS="$7"
    local LDAP_PORT="$8"
    local LDAP_ADMIN_PASS="$9"
    local LDAP_ORG_DISPLAY="${10}"
    local LDAP_DOMAIN="${11}"   # ex: org1.example.com
    local LDAP_BASE_DN="${12}"

    cat <<EOF >> $DOCKER_FILE
  postgres.${SHORTNAME}:
    image: postgres:15
    container_name: postgres.${SHORTNAME}
    environment:
      POSTGRES_DB: ${DB_NAME}
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASS}
    volumes:
      - pgdata.${SHORTNAME}:/var/lib/postgresql/data
    ports:
      - "${DB_PORT}:5432"
    networks:
      - fabric

  ldap.${SHORTNAME}:
    image: osixia/openldap:1.5.0
    container_name: ldap.${SHORTNAME}
    environment:
      LDAP_ORGANISATION: "${LDAP_ORG_DISPLAY}"
      LDAP_DOMAIN: "${LDAP_DOMAIN}"
      LDAP_ADMIN_PASSWORD: "${LDAP_ADMIN_PASS}"
      LDAP_BASE_DN: "${LDAP_BASE_DN}"
      LDAP_REMOVE_CONFIG_AFTER_SETUP: "false"
    volumes:
      - ${FABRIC_CA_DIR}/${SHORTNAME}/ldap-bootstrap:/container/service/slapd/assets/config/bootstrap/ldif/custom
      - ldapdata.${SHORTNAME}:/var/lib/ldap
      - ldapconfig.${SHORTNAME}:/etc/ldap/slapd.d
    ports:
      - "${LDAP_PORT}:389"
    networks:
      - fabric

  ca.${SHORTNAME}:
    image: hyperledger/fabric-ca:1.5
    container_name: ca.${SHORTNAME}
    command: sh -c 'fabric-ca-server start -c /etc/hyperledger/fabric-ca-server/fabric-ca-server-config.yaml'
    environment:
      FABRIC_CA_SERVER_HOME: /etc/hyperledger/fabric-ca-server
    volumes:
      - ${FABRIC_CA_DIR}/${SHORTNAME}/fabric-ca-server-config.yaml:/etc/hyperledger/fabric-ca-server/fabric-ca-server-config.yaml
      - ca-data.${SHORTNAME}:/etc/hyperledger/fabric-ca-server/msp
    ports:
      - "${CA_PORT}:${CA_PORT}"
      - "${OP_PORT}:${OP_PORT}"
    networks:
      - fabric
    depends_on:
      - postgres.${SHORTNAME}
      - ldap.${SHORTNAME}

EOF
}

# CA/DB/LDAP de l'Orderer
ORDERER_LDAP_DN=$(domain_to_dn "$ORDERER_DOMAIN")
append_ca_stack "orderer" "$ORDERER_CA_PORT" "$ORDERER_CA_OPERATIONS_PORT" "$ORDERER_DB_PORT" \
    "$ORDERER_DB_NAME" "$ORDERER_DB_USER" "$ORDERER_DB_PASS" \
    "$ORDERER_LDAP_PORT" "$ORDERER_LDAP_ADMIN_PASS" "OrdererOrg" "$ORDERER_DOMAIN" "$ORDERER_LDAP_DN"

# CA/DB/LDAP de chaque organisation
for ((i=1; i<=NUM_ORGS; i++)); do
    NAME_VAR="ORG${i}_NAME"; DOMAIN_VAR="ORG${i}_DOMAIN"
    CA_PORT_VAR="ORG${i}_CA_PORT"; OP_PORT_VAR="ORG${i}_CA_OPERATIONS_PORT"
    DB_PORT_VAR="ORG${i}_DB_PORT"; DB_NAME_VAR="ORG${i}_DB_NAME"
    DB_USER_VAR="ORG${i}_DB_USER"; DB_PASS_VAR="ORG${i}_DB_PASS"
    LDAP_PORT_VAR="ORG${i}_LDAP_PORT"; LDAP_PASS_VAR="ORG${i}_LDAP_ADMIN_PASS"

    ORG_LDAP_DN=$(domain_to_dn "${!DOMAIN_VAR}")
    append_ca_stack "${!NAME_VAR}" "${!CA_PORT_VAR}" "${!OP_PORT_VAR}" "${!DB_PORT_VAR}" \
        "${!DB_NAME_VAR}" "${!DB_USER_VAR}" "${!DB_PASS_VAR}" \
        "${!LDAP_PORT_VAR}" "${!LDAP_PASS_VAR}" "${!NAME_VAR}" "${!DOMAIN_VAR}" "$ORG_LDAP_DN"
done

# ---- Peers (MSP/TLS servis désormais par ${ORG_ROOT_DIR}, alimenté par enroll-network.sh) ----
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
      - ${ORG_ROOT_DIR}/peerOrganizations/${!DOMAIN_VAR}/peers/peer${p}.${!DOMAIN_VAR}/msp:/etc/hyperledger/fabric/msp:ro
      - ${ORG_ROOT_DIR}/peerOrganizations/${!DOMAIN_VAR}/peers/peer${p}.${!DOMAIN_VAR}/tls:/etc/hyperledger/fabric/tls:ro
      - ${ORG_ROOT_DIR}/ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}/tls:/etc/hyperledger/orderer/tls:ro
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

# ---- CLI admin par organisation (optionnel) ----
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
      - ${ORG_ROOT_DIR}/peerOrganizations/${!DOMAIN_VAR}/users/Admin@${!DOMAIN_VAR}/msp:/etc/hyperledger/fabric/admin-msp:ro
      - ${ORG_ROOT_DIR}/peerOrganizations/${!DOMAIN_VAR}/peers/peer0.${!DOMAIN_VAR}/tls:/etc/hyperledger/fabric/tls:ro
      - ${ORG_ROOT_DIR}/ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}/tls:/etc/hyperledger/orderer/tls:ro
      - ${CHANNEL_ARTIFACTS_DIR}:/var/hyperledger/orderer/channel-artifacts
      - ${ORG_ROOT_DIR}:/etc/hyperledger/fabric/organizations:ro
    networks:
      - fabric
    depends_on:
      - orderer.${ORDERER_DOMAIN}
      - peer0.${!DOMAIN_VAR}

EOF
  fi
done

# ---- Orderer ----
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
      - ${ORG_ROOT_DIR}/ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}/msp:/var/hyperledger/orderer/msp:ro
      - ${ORG_ROOT_DIR}/ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}/tls:/var/hyperledger/orderer/tls:ro
      - ${CHANNEL_ARTIFACTS_DIR}:/var/hyperledger/orderer/channel-artifacts
      - orderer.${ORDERER_DOMAIN}:/var/hyperledger/production/orderer
    ports:
      - "7050:7050"
      - "7053:7053"
    networks:
      - fabric

volumes:
EOF

echo "  orderer.${ORDERER_DOMAIN}:" >> $DOCKER_FILE
echo "  ca-data.orderer:" >> $DOCKER_FILE
echo "  pgdata.orderer:" >> $DOCKER_FILE
echo "  ldapdata.orderer:" >> $DOCKER_FILE
echo "  ldapconfig.orderer:" >> $DOCKER_FILE

for ((i=1;i<=NUM_ORGS;i++)); do
  NAME_VAR="ORG${i}_NAME"
  echo "  ca-data.${!NAME_VAR}:" >> $DOCKER_FILE
  echo "  pgdata.${!NAME_VAR}:" >> $DOCKER_FILE
  echo "  ldapdata.${!NAME_VAR}:" >> $DOCKER_FILE
  echo "  ldapconfig.${!NAME_VAR}:" >> $DOCKER_FILE
done

echo ""
echo "✓ docker-compose.yaml généré (CA + PostgreSQL + LDAP + peers + orderer)"

# =================================================================
# 4. GÉNÉRATION DU CONFIGTX.YAML DYNAMIQUE (déjà généralisé pour N orgs)
# =================================================================
echo "==> Génération de $CONFIG_FILE..."
echo "" > $CONFIG_FILE

cat << EOF >> $CONFIG_FILE
Organizations:
    - &OrdererOrg
        Name: OrdererOrg
        ID: OrdererMSP
        MSPDir: ${ORG_ROOT_DIR}/ordererOrganizations/${ORDERER_DOMAIN}/msp
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
        MSPDir: ${ORG_ROOT_DIR}/peerOrganizations/${!DOMAIN_VAR}/msp
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
echo "                      ClientTLSCert: ${ORG_ROOT_DIR}/ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}/tls/server.crt" >> $CONFIG_FILE
echo "                      ServerTLSCert: ${ORG_ROOT_DIR}/ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}/tls/server.crt" >> $CONFIG_FILE
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
    echo "                      ClientTLSCert: ${ORG_ROOT_DIR}/ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}/tls/server.crt" >> $CONFIG_FILE
    echo "                      ServerTLSCert: ${ORG_ROOT_DIR}/ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}/tls/server.crt" >> $CONFIG_FILE
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
# 5. ÉTAPES SUIVANTES
# =================================================================
mkdir -p "$ARTIFACTS_DIR" "$ORG_ROOT_DIR"

echo ""
echo "✅ Configuration et docker-compose générés avec succès !"
echo ""
echo "Prochaines étapes :"
echo "  1. docker-compose up -d postgres.orderer ldap.orderer ca.orderer \\"
for ((i=1; i<=NUM_ORGS; i++)); do
    NAME_VAR="ORG${i}_NAME"
    echo "       postgres.${!NAME_VAR} ldap.${!NAME_VAR} ca.${!NAME_VAR} \\"
done
echo "     (démarre uniquement la couche PKI : DB + LDAP + Fabric-CA)"
echo ""
echo "  2. ./enroll-network.sh"
echo "     (registre/enrôle toutes les identités auprès de chaque Fabric-CA"
echo "      et construit l'arborescence ${ORG_ROOT_DIR}/ attendue par Fabric)"
echo ""
echo "  3. ./generate-ldap-identities.sh"
echo "     (lit configtx.yaml, génère les groupes RBAC + utilisateurs LDAP"
echo "      avec mots de passe hashés SSHA dans ${FABRIC_CA_DIR}/<org>/ldap-bootstrap/ ;"
echo "      première exécution = crée des modèles CSV à éditer dans ./ldap-users/)"
echo ""
echo "  4. export FABRIC_CFG_PATH=\${PWD} && configtxgen -profile MultiOrgsOrdererGenesis -channelID system-channel -outputBlock /dev/null"
echo "     (vérifie que configtx.yaml est valide, optionnel)"
echo ""
echo "  5. Pour chaque canal :"
echo "       configtxgen -profile Profile_<canal> -outputBlock ${ARTIFACTS_DIR}/<canal>_genesis.block -channelID <canal>"
echo ""
echo "  6. docker-compose up -d"
echo "     (démarre l'orderer, les peers, les CLI ; les conteneurs ldap.<org>"
echo "      chargeront le bootstrap LDIF généré à l'étape 3)"
echo ""
echo "  7. Rejoindre les canaux via osnadmin / peer channel join, comme d'habitude."