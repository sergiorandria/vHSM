#!/bin/bash
set -e

# =================================================================
#  ENROLL-NETWORK.SH
#  Registre puis enrôle toutes les identités (admins, orderer, peers,
#  utilisateur applicatif) auprès des serveurs Fabric-CA démarrés par
#  docker-compose, et construit l'arborescence "organizations/" attendue
#  par les peers / l'orderer / configtxgen (même mise en page que
#  cryptogen : peerOrganizations/<domain>/..., ordererOrganizations/...).
#
#  Pré-requis : `docker-compose up -d` a déjà démarré au moins les
#  services postgres.*, ldap.* et ca.* (voir generate-network.sh).
# =================================================================

ENV_FILE="network.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "❌ $ENV_FILE introuvable. Lancez d'abord ./generate-network.sh"
    exit 1
fi
source "$ENV_FILE"

CA_CLIENT_IMAGE="hyperledger/fabric-ca:1.5"
NETWORK_NAME="fabric"
HOST_ORG_ROOT="$(pwd)/$(echo ${ORG_ROOT_DIR} | sed 's/^\.\///')"
mkdir -p "$HOST_ORG_ROOT"

# UID/GID de l'utilisateur courant sur l'hôte : tous les conteneurs
# jetables lancés ci-dessous s'exécutent avec cette identité afin que
# les fichiers écrits dans ${HOST_ORG_ROOT} (monté depuis le conteneur)
# appartiennent à cet utilisateur, jamais à root.
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

# -----------------------------------------------------------------
# Exécute une commande fabric-ca-client dans un conteneur jetable,
# avec ${ORG_ROOT_DIR} monté sur /organizations (persistant sur l'hôte).
#   $1 = FABRIC_CA_CLIENT_HOME (chemin RELATIF sous /organizations)
#   $@ = reste des arguments passés à fabric-ca-client
# -----------------------------------------------------------------
fca_client() {
    local HOME_REL="$1"; shift
    docker run --rm --network "$NETWORK_NAME" \
        --user "${HOST_UID}:${HOST_GID}" \
        -e FABRIC_CA_CLIENT_HOME="/organizations/${HOME_REL}" \
        -e HOME="/organizations/${HOME_REL}" \
        -v "${HOST_ORG_ROOT}:/organizations" \
        "$CA_CLIENT_IMAGE" fabric-ca-client "$@"
}

wait_for_ca() {
    local HOST="$1"
    local PORT="$2"
    local CANAME="$3"
    echo "   ... attente de ${HOST}:${PORT}"
    for i in $(seq 1 30); do
        if docker run --rm --network "$NETWORK_NAME" \
            --user "${HOST_UID}:${HOST_GID}" \
            -e HOME=/tmp \
            "$CA_CLIENT_IMAGE" \
            fabric-ca-client getcainfo -u "http://${HOST}:${PORT}" --caname "${CANAME}" \
            --mspdir "/tmp/getcainfo-${HOST}" >/dev/null 2>&1; then
            echo "   ✓ ${HOST}:${PORT} disponible"
            return 0
        fi
        sleep 2
    done
    echo "❌ Timeout en attendant ${HOST}:${PORT}. Vérifiez 'docker-compose logs ${HOST}'."
    exit 1
}

# Écrit le config.yaml NodeOUs dans un dossier msp donné.
#   $1 = chemin hôte du dossier msp
#   $2 = nom du fichier de certificat racine (dans cacerts/)
write_nodeous_config() {
    local MSP_DIR="$1"
    local CACERT_FILE="$2"
    cat << EOF > "${MSP_DIR}/config.yaml"
NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/${CACERT_FILE}
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/${CACERT_FILE}
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/${CACERT_FILE}
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/${CACERT_FILE}
    OrganizationalUnitIdentifier: orderer
EOF
}

# Enrôle une identité pour obtenir son certificat MSP + son certificat TLS,
# range le résultat dans la mise en page attendue par Fabric.
#   $1 = shortname CA (ex: org1 / orderer)
#   $2 = port CA
#   $3 = id.name          (ex: peer0, orgadmin, orderer)
#   $4 = id.secret
#   $5 = dossier de destination HOTE (ex: organizations/peerOrganizations/org1.../peers/peer0.org1...)
#   $6 = hostname(s) à mettre dans le SAN du certificat TLS (le nom du conteneur)
enroll_identity() {
    local CA_SHORT="$1" CA_PORT="$2" ID_NAME="$3" ID_SECRET="$4"
    local DEST_REL="$5" TLS_HOST="$6"
    local CA_HOST="ca.${CA_SHORT}"
    local CA_NAME="ca-${CA_SHORT}"

    mkdir -p "${HOST_ORG_ROOT}/${DEST_REL}/msp" "${HOST_ORG_ROOT}/${DEST_REL}/tls-tmp"

    # --- certificat MSP (signature) ---
    fca_client "${DEST_REL}" enroll \
        -u "http://${ID_NAME}:${ID_SECRET}@${CA_HOST}:${CA_PORT}" \
        --caname "${CA_NAME}" \
        --mspdir "/organizations/${DEST_REL}/msp"

    # --- certificat TLS ---
    fca_client "${DEST_REL}" enroll \
        -u "http://${ID_NAME}:${ID_SECRET}@${CA_HOST}:${CA_PORT}" \
        --caname "${CA_NAME}" \
        --enrollment.profile tls \
        --csr.hosts "${TLS_HOST}" --csr.hosts localhost \
        --mspdir "/organizations/${DEST_REL}/tls-tmp"

    local TLS_DIR="${HOST_ORG_ROOT}/${DEST_REL}/tls"
    mkdir -p "$TLS_DIR"
    cp "${HOST_ORG_ROOT}/${DEST_REL}/tls-tmp/signcerts/"*.pem "${TLS_DIR}/server.crt"
    cp "${HOST_ORG_ROOT}/${DEST_REL}/tls-tmp/keystore/"*_sk "${TLS_DIR}/server.key"
    if [ -d "${HOST_ORG_ROOT}/${DEST_REL}/tls-tmp/tlscacerts" ]; then
        cp "${HOST_ORG_ROOT}/${DEST_REL}/tls-tmp/tlscacerts/"*.pem "${TLS_DIR}/ca.crt"
    else
        cp "${HOST_ORG_ROOT}/${DEST_REL}/tls-tmp/cacerts/"*.pem "${TLS_DIR}/ca.crt"
    fi
    rm -rf "${HOST_ORG_ROOT}/${DEST_REL}/tls-tmp"

    local CACERT_FILE
    CACERT_FILE=$(basename $(ls "${HOST_ORG_ROOT}/${DEST_REL}/msp/cacerts/"*.pem | head -1))
    write_nodeous_config "${HOST_ORG_ROOT}/${DEST_REL}/msp" "${CACERT_FILE}"
}

# Construit le MSP "organisation" (utilisé par configtx.yaml) à partir du
# MSP déjà enrôlé d'une identité de cette organisation (mêmes cacerts).
build_org_level_msp() {
    local SRC_MSP_HOST_DIR="$1"   # ex: ${HOST_ORG_ROOT}/peerOrganizations/org1.../users/Admin@.../msp
    local ORG_MSP_HOST_DIR="$2"   # ex: ${HOST_ORG_ROOT}/peerOrganizations/org1.../msp
    mkdir -p "${ORG_MSP_HOST_DIR}/cacerts" "${ORG_MSP_HOST_DIR}/tlscacerts"
    cp "${SRC_MSP_HOST_DIR}/cacerts/"*.pem "${ORG_MSP_HOST_DIR}/cacerts/"
    # La même CA signe les certs applicatifs et TLS ici : on réutilise le
    # même cacert comme racine de confiance TLS de l'organisation.
    cp "${SRC_MSP_HOST_DIR}/cacerts/"*.pem "${ORG_MSP_HOST_DIR}/tlscacerts/"
    local CACERT_FILE
    CACERT_FILE=$(basename $(ls "${ORG_MSP_HOST_DIR}/cacerts/"*.pem | head -1))
    write_nodeous_config "${ORG_MSP_HOST_DIR}" "${CACERT_FILE}"
}

echo "================================================================="
echo " Enrôlement du réseau (Fabric-CA)"
echo "================================================================="

# -----------------------------------------------------------------
# 1. ORDERER
# -----------------------------------------------------------------
echo ""
echo "==> [Orderer] ${ORDERER_DOMAIN}"
wait_for_ca "ca.orderer" "$ORDERER_CA_PORT" "ca-orderer"

REGISTRAR_HOME="ordererOrganizations/${ORDERER_DOMAIN}/ca-admin"
fca_client "$REGISTRAR_HOME" enroll \
    -u "http://${CA_ADMIN_USER}:${CA_ADMIN_PASS}@ca.orderer:${ORDERER_CA_PORT}" \
    --caname ca-orderer --mspdir "/organizations/${REGISTRAR_HOME}/msp"

fca_client "$REGISTRAR_HOME" register --caname ca-orderer \
    --id.name ordereradmin --id.secret ordereradminpw --id.type admin \
    --mspdir "/organizations/${REGISTRAR_HOME}/msp" || true
fca_client "$REGISTRAR_HOME" register --caname ca-orderer \
    --id.name orderer --id.secret ordererpw --id.type orderer \
    --mspdir "/organizations/${REGISTRAR_HOME}/msp" || true

enroll_identity "orderer" "$ORDERER_CA_PORT" "ordereradmin" "ordereradminpw" \
    "ordererOrganizations/${ORDERER_DOMAIN}/users/Admin@${ORDERER_DOMAIN}" "orderer.${ORDERER_DOMAIN}"

enroll_identity "orderer" "$ORDERER_CA_PORT" "orderer" "ordererpw" \
    "ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}" "orderer.${ORDERER_DOMAIN}"

build_org_level_msp \
    "${HOST_ORG_ROOT}/ordererOrganizations/${ORDERER_DOMAIN}/users/Admin@${ORDERER_DOMAIN}/msp" \
    "${HOST_ORG_ROOT}/ordererOrganizations/${ORDERER_DOMAIN}/msp"

echo "   ✓ Orderer enrôlé"

# -----------------------------------------------------------------
# 2. ORGANISATIONS DE PEERS
# -----------------------------------------------------------------
for ((i=1; i<=NUM_ORGS; i++)); do
    NAME_VAR="ORG${i}_NAME"; SHORTNAME="${!NAME_VAR}"
    DOMAIN_VAR="ORG${i}_DOMAIN"; DOMAIN="${!DOMAIN_VAR}"
    CA_PORT_VAR="ORG${i}_CA_PORT"; CA_PORT="${!CA_PORT_VAR}"
    PEERS_VAR="ORG${i}_PEERS"; NUM_PEERS="${!PEERS_VAR}"

    echo ""
    echo "==> [${SHORTNAME}] ${DOMAIN}"
    wait_for_ca "ca.${SHORTNAME}" "$CA_PORT" "ca-${SHORTNAME}"

    REGISTRAR_HOME="peerOrganizations/${DOMAIN}/ca-admin"
    fca_client "$REGISTRAR_HOME" enroll \
        -u "http://${CA_ADMIN_USER}:${CA_ADMIN_PASS}@ca.${SHORTNAME}:${CA_PORT}" \
        --caname "ca-${SHORTNAME}" --mspdir "/organizations/${REGISTRAR_HOME}/msp"

    fca_client "$REGISTRAR_HOME" register --caname "ca-${SHORTNAME}" \
        --id.name orgadmin --id.secret orgadminpw --id.type admin --id.affiliation "${SHORTNAME}" \
        --mspdir "/organizations/${REGISTRAR_HOME}/msp" || true
    fca_client "$REGISTRAR_HOME" register --caname "ca-${SHORTNAME}" \
        --id.name user1 --id.secret user1pw --id.type client --id.affiliation "${SHORTNAME}" \
        --mspdir "/organizations/${REGISTRAR_HOME}/msp" || true

    for ((p=0; p<NUM_PEERS; p++)); do
        fca_client "$REGISTRAR_HOME" register --caname "ca-${SHORTNAME}" \
            --id.name "peer${p}" --id.secret "peer${p}pw" --id.type peer --id.affiliation "${SHORTNAME}" \
            --mspdir "/organizations/${REGISTRAR_HOME}/msp" || true
    done

    enroll_identity "${SHORTNAME}" "$CA_PORT" "orgadmin" "orgadminpw" \
        "peerOrganizations/${DOMAIN}/users/Admin@${DOMAIN}" "Admin@${DOMAIN}"

    enroll_identity "${SHORTNAME}" "$CA_PORT" "user1" "user1pw" \
        "peerOrganizations/${DOMAIN}/users/User1@${DOMAIN}" "User1@${DOMAIN}"

    for ((p=0; p<NUM_PEERS; p++)); do
        enroll_identity "${SHORTNAME}" "$CA_PORT" "peer${p}" "peer${p}pw" \
            "peerOrganizations/${DOMAIN}/peers/peer${p}.${DOMAIN}" "peer${p}.${DOMAIN}"
    done

    build_org_level_msp \
        "${HOST_ORG_ROOT}/peerOrganizations/${DOMAIN}/users/Admin@${DOMAIN}/msp" \
        "${HOST_ORG_ROOT}/peerOrganizations/${DOMAIN}/msp"

    echo "   ✓ ${SHORTNAME} enrôlé (admin, user1, ${NUM_PEERS} peer(s))"
done

# -----------------------------------------------------------------
# 3. FILET DE SÉCURITÉ : garantir que TOUT est bien à user:user
# -----------------------------------------------------------------
# Les conteneurs tournent désormais avec --user "${HOST_UID}:${HOST_GID}",
# donc les fichiers écrits par fabric-ca-client appartiennent déjà à
# l'utilisateur courant. Ce chown est une sécurité supplémentaire pour
# couvrir d'éventuels fichiers créés autrement (ex: anciens runs, cp/mkdir
# côté hôte lancés via sudo, etc.) : il ne fait rien si tout est déjà bon.
if command -v sudo >/dev/null 2>&1; then
    sudo chown -R "${HOST_UID}:${HOST_GID}" "$HOST_ORG_ROOT" 2>/dev/null || \
        chown -R "${HOST_UID}:${HOST_GID}" "$HOST_ORG_ROOT" 2>/dev/null || true
else
    chown -R "${HOST_UID}:${HOST_GID}" "$HOST_ORG_ROOT" 2>/dev/null || true
fi

echo ""
echo "================================================================="
echo "✅ Enrôlement terminé. Arborescence générée dans ${ORG_ROOT_DIR}/"
echo "   (propriété : $(id -un):$(id -gn), UID:GID ${HOST_UID}:${HOST_GID})"
echo "================================================================="
echo ""
echo "Prochaine étape : générer les blocs de canaux puis démarrer le reste"
echo "du réseau, par exemple :"
echo "  export FABRIC_CFG_PATH=\${PWD}"
echo "  configtxgen -profile Profile_<canal> -outputBlock ${CHANNEL_ARTIFACTS_DIR}/<canal>_genesis.block -channelID <canal>"
echo "  docker-compose up -d"