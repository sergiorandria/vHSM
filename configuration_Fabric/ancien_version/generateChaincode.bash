#!/bin/bash
set -e

# =================================================================
# SCRIPT INTERACTIF DE PACKAGING DES CHAINCODES
# =================================================================
# Détecte automatiquement les canaux déjà créés par generate-network.sh
# (lus depuis network.env) et demande, pour chacun, le chaincode à packager :
# nom, version, et chemin source Go (fourni au préalable par l'utilisateur).
#
# Séparé de generate-network.sh car il dépend des conteneurs CLI Docker
# déjà démarrés (docker-compose up -d).
#
# Prérequis avant de lancer ce script :
#   1. ./generate-network.sh a déjà été exécuté (network.env, crypto-config/,
#      docker-compose.yaml existent, et les canaux sont définis).
#   2. docker-compose up -d a démarré les peers, l'orderer, et les conteneurs CLI.
#   3. Au moins une organisation par canal a répondu "oui" à la question du CLI
#      lors du questionnaire réseau (ORG<i>_HAS_CLI=yes).
# =================================================================

ENV_FILE="network.env"

if [ ! -f "$ENV_FILE" ]; then
    echo "❌ Erreur : '$ENV_FILE' introuvable. Lancez d'abord ./generate-network.sh."
    exit 1
fi

# Chargement des variables réseau/canaux déjà générées
source $ENV_FILE
export PATH=$(realpath "${FABRIC_BIN_DIR}"):$PATH

if [ -z "$NUM_CHANNELS" ] || [ "$NUM_CHANNELS" -lt 1 ]; then
    echo "❌ Aucun canal détecté dans '$ENV_FILE'. Avez-vous bien généré le réseau au préalable ?"
    exit 1
fi

CHAINCODE_ROOT="./chaincode"
mkdir -p "$CHAINCODE_ROOT"

echo "================================================================="
echo "   PACKAGING INTERACTIF DES CHAINCODES                           "
echo "================================================================="
echo "Canaux détectés dans '$ENV_FILE' : $NUM_CHANNELS"
echo ""

# Affichage récapitulatif des canaux disponibles avant de commencer
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
        read -p "Voulez-vous packager un chaincode pour ce canal ? (o/n) [o]: " DO_PACKAGE
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

    # --- Collecte interactive des informations du chaincode pour ce canal ---
    read -p "    Nom du chaincode (ex: mycc): " CC_NAME
    read -p "    Version du chaincode [1.0]: " CC_VERSION
    CC_VERSION=${CC_VERSION:-"1.0"}

    while true; do
        read -p "    Chemin hôte du code source Go du chaincode (ex: ./chaincode-src/mycc): " CC_SRC_PATH
        if [ -d "$CC_SRC_PATH" ]; then
            break
        else
            echo "    ⚠️  Le dossier '$CC_SRC_PATH' n'existe pas ou n'est pas accessible. Réessayez."
        fi
    done

    # Dossier dédié au chaincode de ce canal : chaincode/<canal>/src + .tar.gz généré
    CHANNEL_CC_DIR="${CHAINCODE_ROOT}/${CH_NAME}"
    CHANNEL_CC_SRC_DIR="${CHANNEL_CC_DIR}/src"
    mkdir -p "$CHANNEL_CC_SRC_DIR"

    echo "    -> Copie du code source depuis '${CC_SRC_PATH}' vers '${CHANNEL_CC_SRC_DIR}'..."
    cp -r "${CC_SRC_PATH}/." "$CHANNEL_CC_SRC_DIR/"

    # Détermination de la première organisation du canal pour servir de CLI de packaging
    FIRST_ORG_IDX=$(echo "${!CH_ORGS_VAR}" | awk '{print $1}')
    PKG_DOMAIN_VAR="ORG${FIRST_ORG_IDX}_DOMAIN"
    PKG_HAS_CLI_VAR="ORG${FIRST_ORG_IDX}_HAS_CLI"
    PKG_DOMAIN="${!PKG_DOMAIN_VAR}"

    if [ "${!PKG_HAS_CLI_VAR}" != "yes" ]; then
        echo "    ⚠️  Aucun conteneur CLI actif pour l'organisation en charge du packaging (org ${FIRST_ORG_IDX})."
        echo "       Le code source a été placé dans '${CHANNEL_CC_SRC_DIR}', mais le .tar.gz n'a pas été généré."
        echo "       Activez le CLI pour cette organisation dans network.env (ORG${FIRST_ORG_IDX}_HAS_CLI=yes),"
        echo "       relancez ./generate-network.sh puis docker-compose up -d, et relancez ce script."
        continue
    fi

    CLI_CONTAINER="cli.${PKG_DOMAIN}"
    CC_LABEL="${CC_NAME}_${CC_VERSION}"
    CONTAINER_SRC_PATH="/opt/gopath/src/github.com/hyperledger/fabric/peer/chaincode-build/${CH_NAME}"

    # Vérifier que le conteneur CLI est bien démarré avant de tenter le packaging
    if [ -z "$(docker ps -q -f name=^/${CLI_CONTAINER}$)" ]; then
        echo "    ⚠️  Le conteneur '${CLI_CONTAINER}' n'est pas démarré."
        echo "       Le code source a été placé dans '${CHANNEL_CC_SRC_DIR}', mais le .tar.gz n'a pas été généré."
        echo "       Lancez 'docker-compose up -d', puis relancez ce script pour finaliser le packaging."
        continue
    fi

    echo "    -> Packaging via le conteneur CLI '${CLI_CONTAINER}'..."

    set +e

    # Copie du code source dans le conteneur CLI (le bind-mount ne couvre que crypto-config/artifacts)
    docker exec "${CLI_CONTAINER}" mkdir -p "${CONTAINER_SRC_PATH}"
    docker cp "${CHANNEL_CC_SRC_DIR}/." "${CLI_CONTAINER}:${CONTAINER_SRC_PATH}"

    # Génération du package .tar.gz directement dans channel-artifacts (déjà monté en écriture sur le CLI)
    docker exec "${CLI_CONTAINER}" peer lifecycle chaincode package \
        "/var/hyperledger/orderer/channel-artifacts/${CC_LABEL}.tar.gz" \
        --path "${CONTAINER_SRC_PATH}" \
        --lang golang \
        --label "${CC_LABEL}"
    PACKAGE_STATUS=$?

    set -e

    if [ $PACKAGE_STATUS -ne 0 ]; then
        echo "    ❌ Le packaging a échoué pour le canal '${CH_NAME}'. Vérifiez les messages ci-dessus."
        continue
    fi

    # Copie du résultat vers le dossier dédié du chaincode pour ce canal, sur l'hôte.
    # On utilise "docker cp" depuis le conteneur plutôt qu'un "cp" local, car le fichier
    # a été créé par le processus du conteneur (souvent root) et peut être illisible
    # directement pour l'utilisateur de l'hôte selon les permissions du volume partagé.
    docker cp "${CLI_CONTAINER}:/var/hyperledger/orderer/channel-artifacts/${CC_LABEL}.tar.gz" "${CHANNEL_CC_DIR}/${CC_LABEL}.tar.gz"

    echo "    ✓ Package généré : ${CHANNEL_CC_DIR}/${CC_LABEL}.tar.gz"
done

echo ""
echo "================================================================="
echo "✅ Packaging interactif terminé. Structure :"
echo "   chaincode/<canal>/src/            -> code source Go copié"
echo "   chaincode/<canal>/<label>.tar.gz  -> package prêt pour 'peer lifecycle chaincode install'"