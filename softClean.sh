#!/bin/bash

# Quitter le script en cas d'erreur
set -e

# --- CONFIGURATION DES MÊMES CHEMINS ---
SOFTHSM_DIR="$HOME/softhsm2_project"
ENV_FILE="$SOFTHSM_DIR/env.sh"

echo "=================================================="
echo " Nettoyage et Réinitialisation de SoftHSMv2"
echo "=================================================="

# 1. Demande de confirmation pour éviter les accidents
read -p "[?] Êtes-vous sûr de vouloir supprimer TOUTES les configurations et clés SoftHSMv2 ? (y/N) : " confirmation
if [[ ! "$confirmation" =~ ^[Yy]$ ]]; then
    echo "[X] Opération annulée."
    exit 0
fi

# 2. Suppression des fichiers et répertoires
if [ -d "$SOFTHSM_DIR" ]; then
    echo "[*] Suppression du répertoire du projet ($SOFTHSM_DIR)..."
    # Supprime les tokens, la config softhsm2.conf et env.sh d'un coup
    rm -rf "$SOFTHSM_DIR"
    echo "[✓] Fichiers supprimés avec succès."
else
    echo "[!] Aucun répertoire trouvé dans $SOFTHSM_DIR. Rien à supprimer."
fi

# 3. Instructions pour vider l'environnement du terminal actuel
echo "=================================================="
echo " Nettoyage terminé !"
echo "=================================================="
echo "Les fichiers physiques ont été supprimés."
echo "Pour nettoyer les variables de votre terminal actuel, exécutez :"
echo ""
echo "unset SOFTHSM2_CONF HSM_PIN PKCS11_PIN SOFTHSM_SO_PIN"
echo ""
echo "Note : Si vous aviez ajouté la variable dans votre ~/.bashrc,"
echo "pensez à ouvrir ce fichier pour retirer la ligne export."
echo "=================================================="
