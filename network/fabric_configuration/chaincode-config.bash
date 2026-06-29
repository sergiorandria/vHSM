#!/bin/bash
set -e

ENV_FILE="network.env"
DOCKER_FILE="docker-compose.yaml"
CHAINCODE_SERVER_PORT=9999
HEALTHCHECK_TIMEOUT=60   # secondes max d'attente du démarrage du serveur chaincode
HEALTHCHECK_INTERVAL=2   # secondes entre deux tentatives

if [ ! -f "$ENV_FILE" ]; then
    echo "❌ Erreur : '$ENV_FILE' introuvable. Lancez d'abord ./generate-network.sh."
    exit 1
fi
if [ ! -f "$DOCKER_FILE" ]; then
    echo "❌ Erreur : '$DOCKER_FILE' introuvable. Lancez d'abord ./generate-network.sh."
    exit 1
fi

source $ENV_FILE
export PATH=$(realpath "${FABRIC_BIN_DIR}"):$PATH

if [ -z "$NUM_CHANNELS" ] || [ "$NUM_CHANNELS" -lt 1 ]; then
    echo "❌ Aucun canal détecté dans '$ENV_FILE'. Avez-vous bien généré le réseau au préalable ?"
    exit 1
fi

CHAINCODE_ROOT="./chaincode"
mkdir -p "$CHAINCODE_ROOT"

# -----------------------------------------------------------------
# Fonction utilitaire : insère un bloc de service YAML dans docker-compose.yaml,
# juste avant la ligne "volumes:" qui clôt la section "services:".
# Idempotent : si le service existe déjà (même container_name), il est d'abord
# retiré avant réinsertion, pour permettre de relancer ce script sans dupliquer.
# -----------------------------------------------------------------
inject_compose_service() {
    local service_block_file="$1"
    local container_name="$2"

    # Retrait d'un bloc existant portant le même container_name, s'il existe déjà
    # (recherche le service par son nom de conteneur et supprime tout le bloc
    # jusqu'à la prochaine ligne de service ou "volumes:").
    python3 - "$DOCKER_FILE" "$container_name" << 'PYEOF'
import sys, re

compose_path, target_name = sys.argv[1], sys.argv[2]
with open(compose_path) as f:
    lines = f.readlines()

out = []
skip = False
for i, line in enumerate(lines):
    if not skip and line.strip().startswith("container_name: " + target_name):
        # Retire en arrière jusqu'au début de ce bloc de service (ligne "  <nom>:" à 2 espaces d'indentation)
        while out and not re.match(r"^  \S.*:\s*$", out[-1]):
            out.pop()
        if out:
            out.pop()  # retire aussi la ligne d'en-tête du service "  <nom>:"
        skip = True
        continue
    if skip:
        # On arrête de sauter dès qu'on retombe sur une nouvelle entrée de service
        # (indentation 2 espaces suivie de texte et ":") ou sur "volumes:"
        if re.match(r"^  \S.*:\s*$", line) or line == "volumes:\n":
            skip = False
        else:
            continue
    out.append(line)

with open(compose_path, "w") as f:
    f.writelines(out)
PYEOF

    # Insertion du nouveau bloc juste avant la ligne "volumes:"
    python3 - "$DOCKER_FILE" "$service_block_file" << 'PYEOF'
import sys

compose_path, block_path = sys.argv[1], sys.argv[2]
with open(compose_path) as f:
    lines = f.readlines()
with open(block_path) as f:
    block = f.read()

out = []
inserted = False
for line in lines:
    if not inserted and line == "volumes:\n":
        out.append(block)
        inserted = True
    out.append(line)

if not inserted:
    out.append(block)

with open(compose_path, "w") as f:
    f.writelines(out)
PYEOF
}

echo "================================================================="
echo "   DÉPLOIEMENT AUTOMATISÉ DES CHAINCODES (MODE CCaaS / TLS)       "
echo "================================================================="
echo "Canaux détectés dans '$ENV_FILE' : $NUM_CHANNELS"
echo ""

for ((c=1; c<=NUM_CHANNELS; c++)); do
    CH_NAME_VAR="CH${c}_NAME"
    CH_ORGS_VAR="CH${c}_ORGS"
    echo "  [$c] ${!CH_NAME_VAR}  (organisations : ${!CH_ORGS_VAR})"
done
echo ""

for ((c=1; c<=NUM_CHANNELS; c++)); do
    CH_NAME_VAR="CH${c}_NAME"
    CH_ORGS_VAR="CH${c}_ORGS"
    CH_NAME="${!CH_NAME_VAR}"

    echo "================================================================="
    echo "--- Canal [$c] : '${CH_NAME}' ---"

    while true; do
        read -p "Voulez-vous déployer un chaincode CCaaS pour ce canal ? (o/n) [o]: " DO_PACKAGE
        DO_PACKAGE=${DO_PACKAGE:-o}
        case "$DO_PACKAGE" in
            [oOyY]) DO_PACKAGE="yes"; break ;;
            [nN]) DO_PACKAGE="no"; break ;;
            *) echo "Réponse invalide, entrez 'o' ou 'n'." ;;
        esac
    done

    if [ "$DO_PACKAGE" == "no" ]; then
        echo "    -> Canal '${CH_NAME}' ignoré."
        continue
    fi

    read -p "    Nom du chaincode (ex: thesis): " CC_NAME
    read -p "    Version du chaincode [1.0]: " CC_VERSION
    CC_VERSION=${CC_VERSION:-"1.0"}

    while true; do
        read -p "    Chemin hôte du code source Go du chaincode (ex: ./template_chainecode): " CC_SRC_PATH
        if [ -d "$CC_SRC_PATH" ]; then
            break
        else
            echo "    ⚠️  Le dossier '$CC_SRC_PATH' n'existe pas ou n'est pas accessible. Réessayez."
        fi
    done

    CC_LABEL="${CC_NAME}_${CC_VERSION}"
    CHANNEL_CC_DIR="${CHAINCODE_ROOT}/${CH_NAME}"
    CHANNEL_CC_SRC_DIR="${CHANNEL_CC_DIR}/src"

    mkdir -p "$CHANNEL_CC_SRC_DIR"
    echo "    -> Copie du code source depuis '${CC_SRC_PATH}' vers '${CHANNEL_CC_SRC_DIR}'..."
    cp -r "${CC_SRC_PATH}/." "$CHANNEL_CC_SRC_DIR/"

    # --- Dockerfile (généré une fois, réutilisé pour tous les peers du canal) ---
    DOCKERFILE_PATH="${CHANNEL_CC_DIR}/Dockerfile"
    if [ ! -f "$DOCKERFILE_PATH" ]; then
        cat << DOCKER_EOF > "$DOCKERFILE_PATH"
FROM golang:1.26-bookworm AS builder
WORKDIR /chaincode
COPY src/ .
RUN go mod tidy && go build -o /chaincode-bin .

FROM debian:bookworm-slim
WORKDIR /chaincode
COPY --from=builder /chaincode-bin /chaincode/chaincode-bin
ENV CHAINCODE_SERVER_ADDRESS=0.0.0.0:${CHAINCODE_SERVER_PORT}
EXPOSE ${CHAINCODE_SERVER_PORT}
ENTRYPOINT ["/chaincode/chaincode-bin"]
DOCKER_EOF
        echo "    ✓ Dockerfile généré : ${DOCKERFILE_PATH}"
    fi

    # --- Construction de l'image (une fois par canal, partagée par tous les peers) ---
    CC_IMAGE="${CC_NAME}-ccaas:${CC_VERSION}"
    echo "    -> Construction de l'image '${CC_IMAGE}'..."
    docker build -t "${CC_IMAGE}" -f "${DOCKERFILE_PATH}" "${CHANNEL_CC_DIR}"

    for org_idx in ${!CH_ORGS_VAR}; do
        NAME_VAR="ORG${org_idx}_NAME"
        DOMAIN_VAR="ORG${org_idx}_DOMAIN"
        PEERS_VAR="ORG${org_idx}_PEERS"
        HAS_CLI_VAR="ORG${org_idx}_HAS_CLI"
        ORG_DOMAIN="${!DOMAIN_VAR}"

        if [ "${!HAS_CLI_VAR}" != "yes" ]; then
            echo "    ⚠️  Organisation '${!NAME_VAR}' : aucun conteneur CLI actif. Ignorée."
            continue
        fi

        CLI_CONTAINER="cli.${ORG_DOMAIN}"
        if [ -z "$(docker ps -q -f name=^/${CLI_CONTAINER}$)" ]; then
            echo "    ⚠️  '${CLI_CONTAINER}' n'est pas démarré. Lancez 'docker compose up -d'. Ignorée."
            continue
        fi

        for ((p=0; p<${!PEERS_VAR}; p++)); do
            PEER_HOST="peer${p}.${ORG_DOMAIN}"
            CC_HOST="cc-peer${p}.${ORG_DOMAIN}"
            CC_CONTAINER_NAME="${CC_HOST}"
            PEER_CC_DIR="${CHANNEL_CC_DIR}/${PEER_HOST}"
            mkdir -p "$PEER_CC_DIR"

            echo ""
            echo "    --- Peer '${PEER_HOST}' (org '${!NAME_VAR}') ---"

            CC_TLS_DIR="${CRYPTO_CONFIG_DIR}/peerOrganizations/${ORG_DOMAIN}/peers/${CC_HOST}/tls"
            if [ ! -d "$CC_TLS_DIR" ]; then
                echo "    ❌ Certificat TLS dédié introuvable : ${CC_TLS_DIR}"
                echo "       Régénérez crypto-config/ avec la version à jour de generate-network.sh."
                continue
            fi

            # --- Ask TLS preference ---
            while true; do
                read -p "    Activer le TLS pour ce chaincode CCaaS ? (o/n) [o]: " DO_TLS
                DO_TLS=${DO_TLS:-o}
                case "$DO_TLS" in
                    [oOyY]) TLS_ENABLED="true"; break ;;
                    [nN])   TLS_ENABLED="false"; break ;;
                    *) echo "Réponse invalide, entrez 'o' ou 'n'." ;;
                esac
            done
            # --- connection.json / metadata.json / package .tar.gz ---
if [ "$TLS_ENABLED" == "true" ]; then
                cat << CONN_EOF > "${PEER_CC_DIR}/connection.json"
{
  "address": "${CC_HOST}:${CHAINCODE_SERVER_PORT}",
  "dial_timeout": "10s",
  "tls_required": true,
  "client_auth_required": false,
  "root_cert": "$(awk 'NF {sub(/\r/, ""); printf "%s\\n", $0}' "${CC_TLS_DIR}/ca.crt")"
}
CONN_EOF
            else
                cat << CONN_EOF > "${PEER_CC_DIR}/connection.json"
{
  "address": "${CC_HOST}:${CHAINCODE_SERVER_PORT}",
  "dial_timeout": "10s",
  "tls_required": false,
  "client_auth_required": false
}
CONN_EOF
            fi

            cat << META_EOF > "${PEER_CC_DIR}/metadata.json"
{
  "type": "ccaas",
  "label": "${CC_LABEL}"
}
META_EOF

            (
                cd "$PEER_CC_DIR"
                tar -czf code.tar.gz connection.json
                tar -czf "${CC_LABEL}.tar.gz" metadata.json code.tar.gz
            )
            echo "    ✓ Package CCaaS généré : ${PEER_CC_DIR}/${CC_LABEL}.tar.gz"
# --- Install FIRST to get the package ID ---
echo "    -> Installation sur '${PEER_HOST}' via '${CLI_CONTAINER}'..."

PEER_PORT_VAR="ORG${org_idx}_PEER${p}_PORT"
PEER_PORT="${!PEER_PORT_VAR:-7051}"

set +e
docker cp "${PEER_CC_DIR}/${CC_LABEL}.tar.gz" \
    "${CLI_CONTAINER}:/var/hyperledger/orderer/channel-artifacts/${CC_LABEL}_${PEER_HOST}.tar.gz"

INSTALL_OUTPUT=$(docker exec -e CORE_PEER_ADDRESS="${PEER_HOST}:${PEER_PORT}" "${CLI_CONTAINER}" \
    peer lifecycle chaincode install \
    "/var/hyperledger/orderer/channel-artifacts/${CC_LABEL}_${PEER_HOST}.tar.gz" 2>&1)
INSTALL_STATUS=$?
set -e

echo "$INSTALL_OUTPUT"

if [ $INSTALL_STATUS -ne 0 ]; then
    echo "    ❌ L'installation a échoué sur '${PEER_HOST}'."
    continue
fi
echo "    ✓ Chaincode '${CC_LABEL}' installé sur '${PEER_HOST}'."

# --- Extract package ID from install output ---
CC_PACKAGE_ID=$(echo "$INSTALL_OUTPUT" | grep -oP 'Chaincode code package identifier: \K\S+')
if [ -z "$CC_PACKAGE_ID" ]; then
    # Fallback: query it
    CC_PACKAGE_ID=$(docker exec -e CORE_PEER_ADDRESS="${PEER_HOST}:${PEER_PORT}" "${CLI_CONTAINER}" \
        peer lifecycle chaincode queryinstalled 2>&1 \
        | grep "${CC_LABEL}" | grep -oP 'Package ID: \K[^,]+')
fi
echo "    ✓ Package ID : ${CC_PACKAGE_ID}"

# --- Now inject and start the container WITH the package ID ---
SERVICE_BLOCK_FILE=$(mktemp)
if [ "$TLS_ENABLED" == "true" ]; then
    cat << SERVICE_EOF > "$SERVICE_BLOCK_FILE"
  ${CC_HOST}:
    image: ${CC_IMAGE}
    container_name: ${CC_CONTAINER_NAME}
    environment:
      CORE_CHAINCODE_ID_NAME: ${CC_PACKAGE_ID}
      CHAINCODE_SERVER_ADDRESS: 0.0.0.0:${CHAINCODE_SERVER_PORT}
      CHAINCODE_TLS_DISABLED: "false"
      CHAINCODE_TLS_CERT: /etc/hyperledger/chaincode/tls/server.crt
      CHAINCODE_TLS_KEY: /etc/hyperledger/chaincode/tls/server.key
      CHAINCODE_TLS_CA: /etc/hyperledger/chaincode/tls/ca.crt
    volumes:
      - ${CC_TLS_DIR}:/etc/hyperledger/chaincode/tls:ro
    networks:
      - fabric
    expose:
      - "${CHAINCODE_SERVER_PORT}"

SERVICE_EOF
else
    cat << SERVICE_EOF > "$SERVICE_BLOCK_FILE"
  ${CC_HOST}:
    image: ${CC_IMAGE}
    container_name: ${CC_CONTAINER_NAME}
    environment:
      CORE_CHAINCODE_ID_NAME: ${CC_PACKAGE_ID}
      CHAINCODE_SERVER_ADDRESS: 0.0.0.0:${CHAINCODE_SERVER_PORT}
      CHAINCODE_TLS_DISABLED: "true"
    networks:
      - fabric
    expose:
      - "${CHAINCODE_SERVER_PORT}"

SERVICE_EOF
fi

echo "    -> Injection du service '${CC_HOST}' dans ${DOCKER_FILE}..."
inject_compose_service "$SERVICE_BLOCK_FILE" "$CC_CONTAINER_NAME"
rm -f "$SERVICE_BLOCK_FILE"

echo "    -> Démarrage du conteneur '${CC_CONTAINER_NAME}'..."
docker compose up -d "${CC_HOST}"

# --- Healthcheck ---
echo -n "    -> Waiting for '${CC_HOST}' to be ready"
elapsed=0
ready=0
while [ $elapsed -lt $HEALTHCHECK_TIMEOUT ]; do
    if docker logs "${CC_CONTAINER_NAME}" 2>&1 | grep -qiE "chaincode server start|listening on|started|serving|running|ready"; then
        ready=1
        break
    fi
    echo -n "."
    sleep $HEALTHCHECK_INTERVAL
    elapsed=$((elapsed + HEALTHCHECK_INTERVAL))
done
echo ""

if [ $ready -ne 1 ]; then
    echo "    ❌ Le serveur chaincode '${CC_HOST}' n'a pas répondu après ${HEALTHCHECK_TIMEOUT}s."
    echo "       Vérifiez 'docker logs ${CC_CONTAINER_NAME}'."
    continue
fi
echo "    ✓ Serveur chaincode '${CC_HOST}' prêt."

done   # closes: for ((p=0; p<${!PEERS_VAR}; p++))
    done       # closes: for org_idx in ${!CH_ORGS_VAR}
done           # closes: for ((c=1; c<=NUM_CHANNELS; c++))

echo ""
echo "================================================================="
echo "   DÉPLOIEMENT TERMINÉ"
echo "================================================================="