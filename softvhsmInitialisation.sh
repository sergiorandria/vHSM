#!/bin/bash

# Quitter le script en cas d'erreur
set -e

# --- CONFIGURATION DES VARIABLES ---
SOFTHSM_DIR="$HOME/softhsm2_project"
CONFIG_FILE="$SOFTHSM_DIR/softhsm2.conf"
TOKENS_DIR="$SOFTHSM_DIR/tokens"
ENV_FILE="$SOFTHSM_DIR/env.sh"

TOKEN_LABEL="MonTokenSecurise"
SO_PIN="12345678"     # PIN Administrateur
HSM_PIN="1234"        # PIN Utilisateur (lu par Go)

# --- CHEMINS VERS LES OUTILS ET BINDINGS ---
# Emplacements après compilation manuelle (sudo make install)
SOFTHSM_UTIL="/usr/local/bin/softhsm2-util"
SOFTHSM_LIB="/usr/local/lib/softhsm/libsofthsm2.so"

# Chemin absolu vers pkcs11-tool (paquet opensc)
PKCS11_TOOL="/usr/bin/pkcs11-tool"

echo "=================================================="
echo " Début de la configuration de SoftHSMv2 (Compilé)"
echo "=================================================="

# 1. Création des répertoires
echo "[*] Création des répertoires dans $SOFTHSM_DIR..."
mkdir -p "$TOKENS_DIR"

# 2. Génération du fichier softhsm2.conf
echo "[*] Génération du fichier de configuration..."
cat << EOF > "$CONFIG_FILE"
directories.tokendir = $TOKENS_DIR
objectstore.backend = file
log.level = INFO
EOF

# 3. Export de la variable pour le processus du script actuel
export SOFTHSM2_CONF="$CONFIG_FILE"

# 4. Création du script d'environnement (env.sh) pour votre terminal
echo "[*] Création du script d'environnement (env.sh)..."
cat << EOF > "$ENV_FILE"
#!/bin/bash
export SOFTHSM2_CONF="$CONFIG_FILE"
export HSM_PIN="$HSM_PIN"
echo "[+] Environnement SoftHSMv2 chargé pour votre serveur Go !"
EOF
chmod +x "$ENV_FILE"

# 5. Vérification de la présence physique des outils
if [ ! -f "$SOFTHSM_UTIL" ]; then
    echo "[!] $SOFTHSM_UTIL introuvable. Avez-vous exécuté 'sudo make install' ?"
    exit 1
fi

if [ ! -f "$PKCS11_TOOL" ]; then
    echo "[!] $PKCS11_TOOL introuvable à l'emplacement indiqué. Vérifiez votre installation d'opensc."
    exit 1
fi

# 6. Initialisation du Token
echo "[*] Initialisation du Token '$TOKEN_LABEL'..."
# On utilise --free pour laisser SoftHSM attribuer le premier Slot libre
$SOFTHSM_UTIL --init-token --free --label "$TOKEN_LABEL" --so-pin "$SO_PIN" --pin "$HSM_PIN"

# 7. Génération de la paire de clés "MyKey" (Le Signer Go)
echo "[*] Génération de la paire de clés 'MyKey' (ECDSA P-256) dans le HSM..."
$PKCS11_TOOL --module "$SOFTHSM_LIB" \
             --login --pin "$HSM_PIN" \
             --keypairgen --key-type EC:prime256v1 \
             --label "MyKey" --id "01"

echo "=================================================="
echo " Configuration réussie et clé 'MyKey' créée !"
echo "=================================================="
echo "1. Chargez l'environnement dans votre terminal :"
echo "   source $ENV_FILE"
echo ""
echo "2. IMPORTANT : Assurez-vous que la ligne 41 de 'main.go' utilise :"
echo "   Path: \"$SOFTHSM_LIB\","
echo ""
echo "3. Lancez votre application :"
echo "   go run main.go validation.go"
echo "=================================================="