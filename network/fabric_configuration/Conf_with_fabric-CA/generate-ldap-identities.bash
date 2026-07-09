#!/bin/bash
set -e

# =================================================================
#  GÉNÉRATION DES IDENTITÉS ET GROUPES LDAP (indépendant du réseau)
#
#  Ce script est volontairement séparé de generate-network.sh :
#   - generate-network.sh ne s'occupe QUE du réseau Fabric (CA,
#     PostgreSQL, docker-compose, configtx.yaml).
#   - generate-ldap-identities.sh lit configtx.yaml pour découvrir,
#     de façon GÉNÉRIQUE (N organisations), la liste des organisations
#     "peer" (Name + domaine déduit du MSPDir), puis demande de façon
#     INTERACTIVE, pour chaque organisation, les utilisateurs à créer
#     (rôle, uid, mot de passe), et génère directement tous les LDIF :
#       - la structure LDAP (ou=users, ou=groups)
#       - les groupes RBAC (groupOfNames), un par rôle rencontré
#         (ex: admin, professeurs, etudiants)
#       - les utilisateurs (inetOrgPerson), avec mot de passe stocké
#         hashé au format SSHA ({SSHA}...), jamais en clair.
#
#  USAGE :
#    ./generate-ldap-identities.sh [chemin/vers/configtx.yaml]
#
#  Sortie, pour chaque organisation <org> :
#      ./fabric-ca/<org>/ldap-bootstrap/01-structure.ldif
#      ./fabric-ca/<org>/ldap-bootstrap/02-groups-init.ldif
#      ./fabric-ca/<org>/ldap-bootstrap/02-groups-add-members.ldif
#      ./fabric-ca/<org>/ldap-bootstrap/03-users.ldif
#  (ce dossier est celui déjà monté par docker-compose.yaml dans le
#   conteneur ldap.<org>, généré par generate-network.sh)
#
#  IMPORTANT — GESTION DES GROUPES / RÔLES SUR PLUSIEURS EXÉCUTIONS :
#    Ce script est réexécuté à chaque ajout d'utilisateur. Or LDAP ne
#    permet pas d'écraser un groupe existant avec `ldapadd` (erreur
#    "Already exists") : il faut distinguer la CRÉATION du groupe
#    (une seule fois) de l'AJOUT DE MEMBRES (à chaque exécution).
#    C'est pourquoi les groupes sont désormais scindés en 2 fichiers :
#      - 02-groups-init.ldif          -> `ldapadd` (créer si absent,
#                                         ignorer "Already exists")
#      - 02-groups-add-members.ldif   -> `ldapmodify` (ajoute
#                                         uniquement les membres créés
#                                         PENDANT CETTE EXÉCUTION ;
#                                         ne touche pas aux membres
#                                         déjà présents dans LDAP)
#
#  Relancer ce script écrase 01-structure.ldif et 03-users.ldif ainsi
#  que 02-groups-init.ldif / 02-groups-add-members.ldif pour les
#  organisations traitées (les mots de passe ne sont jamais relus
#  depuis un fichier : vous les re-saisissez à chaque exécution).
# =================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${1:-configtx.yaml}"
FABRIC_CA_DIR="./fabric-ca"
PROCESSED_ORGS=()

if [ ! -f "$CONFIG_FILE" ]; then
    echo " Fichier introuvable : $CONFIG_FILE" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo " python3 est requis (parsing de configtx.yaml + hash SSHA de secours)." >&2
    exit 1
fi

# =================================================================
# 0. PERMISSIONS
#    ${FABRIC_CA_DIR} est souvent créé (ou touché ensuite) par root,
#    par exemple parce que docker-compose a été lancé avec sudo.
#    Si l'utilisateur courant ne peut pas écrire dedans, on propose de
#    corriger la propriété avant d'aller plus loin, plutôt que de
#    planter en pleine génération avec un "Permission non accordée".
# =================================================================
ensure_writable() {
    local DIR="$1"

    # Le dossier n'existe pas encore : mkdir -p par l'utilisateur courant
    # le créera avec les bonnes permissions, rien à corriger.
    [ ! -d "$DIR" ] && return 0

    if [ -w "$DIR" ]; then
        return 0
    fi

    echo "    ⚠ ${DIR} appartient à un autre utilisateur et n'est pas modifiable par $(whoami)." >&2
    ls -ld "$DIR" >&2

    if ! command -v sudo >/dev/null 2>&1; then
        echo " sudo est introuvable : corrigez manuellement la propriété de ${DIR} puis relancez." >&2
        exit 1
    fi

    read -r -p "    Corriger avec 'sudo chown -R $(id -un):$(id -gn) ${FABRIC_CA_DIR}' ? (o/n) [o]: " FIX_PERMS
    FIX_PERMS=${FIX_PERMS:-o}
    case "$FIX_PERMS" in
        [oOyY])
            sudo chown -R "$(id -un):$(id -gn)" "$FABRIC_CA_DIR"
            ;;
        *)
            echo " Corrigez manuellement les permissions de ${FABRIC_CA_DIR} puis relancez le script." >&2
            exit 1
            ;;
    esac

    if [ ! -w "$DIR" ]; then
        echo " Toujours impossible d'écrire dans ${DIR} après la correction." >&2
        exit 1
    fi
}

# Vérification globale, une fois, sur tout l'arbre fabric-ca/ existant
ensure_writable "$FABRIC_CA_DIR"

# =================================================================
# 1. HASH SSHA
#    Priorité à `slappasswd` (outil standard OpenLDAP, présent avec
#    ldap-utils) ; sinon, secours en python3 (implémentation SSHA
#    identique : SHA1(password + salt) + salt, encodé en base64).
# =================================================================
ssha_hash() {
    local PASSWORD="$1"
    if command -v slappasswd >/dev/null 2>&1; then
        slappasswd -s "$PASSWORD" -h '{SSHA}'
    else
        python3 - "$PASSWORD" << 'PYEOF'
import hashlib, os, base64, sys
password = sys.argv[1].encode("utf-8")
salt = os.urandom(4)
digest = hashlib.sha1(password + salt).digest()
print("{SSHA}" + base64.b64encode(digest + salt).decode("ascii"))
PYEOF
    fi
}

# Convertit un domaine (org1.university.com) en base DN LDAP
domain_to_dn() {
    local DOMAIN="$1"
    echo "dc=$(echo "$DOMAIN" | sed 's/\./,dc=/g')"
}

# Demande un mot de passe (saisie masquée + confirmation), boucle
# jusqu'à ce que les deux saisies correspondent et soient non vides.
prompt_password() {
    local PW1 PW2
    while true; do
        read -r -s -p "      Mot de passe : " PW1; echo >&2
        read -r -s -p "      Confirmer le mot de passe : " PW2; echo >&2
        if [ -z "$PW1" ]; then
            echo "      Le mot de passe ne peut pas être vide, réessayez." >&2
            continue
        fi
        if [ "$PW1" != "$PW2" ]; then
            echo "      Les deux saisies ne correspondent pas, réessayez." >&2
            continue
        fi
        break
    done
    printf '%s' "$PW1"
}

# =================================================================
# 2. DÉCOUVERTE GÉNÉRIQUE DES ORGANISATIONS PEER DANS configtx.yaml
#    (ne dépend pas d'un nombre fixe d'organisations)
# =================================================================
echo "==> Lecture de $CONFIG_FILE ..."

mapfile -t ORG_LINES < <(python3 "${SCRIPT_DIR}/parse_configtx_orgs.py" "$CONFIG_FILE")

if [ "${#ORG_LINES[@]}" -eq 0 ]; then
    echo " Aucune organisation peer trouvée dans $CONFIG_FILE (bloc 'Organizations:' introuvable ou vide)." >&2
    exit 1
fi

echo "   Organisations détectées :"
for ENTRY in "${ORG_LINES[@]}"; do
    ORG_NAME="${ENTRY%%|*}"
    ORG_DOMAIN="${ENTRY##*|}"
    echo "     - ${ORG_NAME}  (domaine: ${ORG_DOMAIN})"
done
echo ""

# =================================================================
# 3. SAISIE INTERACTIVE + GÉNÉRATION DES LDIF, PAR ORGANISATION
# =================================================================
for ENTRY in "${ORG_LINES[@]}"; do
    ORG_NAME="${ENTRY%%|*}"
    ORG_DOMAIN="${ENTRY##*|}"
    BASE_DN=$(domain_to_dn "$ORG_DOMAIN")
    LDAP_BOOTSTRAP_DIR="${FABRIC_CA_DIR}/${ORG_NAME}/ldap-bootstrap"

    echo "================================================================="
    echo "==> Organisation : ${ORG_NAME}  (base DN: ${BASE_DN})"
    echo "================================================================="

    read -r -p "    Configurer les identités LDAP de ${ORG_NAME} maintenant ? (o/n) [o]: " DO_ORG
    DO_ORG=${DO_ORG:-o}
    case "$DO_ORG" in
        [oOyY]) ;;
        *) echo "    -> ${ORG_NAME} ignorée."; echo ""; continue ;;
    esac

    mkdir -p "$LDAP_BOOTSTRAP_DIR"
    ensure_writable "$LDAP_BOOTSTRAP_DIR"

    STRUCT_FILE="${LDAP_BOOTSTRAP_DIR}/01-structure.ldif"
    GROUPS_INIT_FILE="${LDAP_BOOTSTRAP_DIR}/02-groups-init.ldif"
    GROUPS_ADD_MEMBERS_FILE="${LDAP_BOOTSTRAP_DIR}/02-groups-add-members.ldif"
    USERS_FILE="${LDAP_BOOTSTRAP_DIR}/03-users.ldif"

    # --- 01-structure.ldif : OU users + groups ---
    cat << EOF > "$STRUCT_FILE"
dn: ou=users,${BASE_DN}
objectClass: organizationalUnit
ou: users

dn: ou=groups,${BASE_DN}
objectClass: organizationalUnit
ou: groups
EOF

    declare -A ROLE_MEMBERS   # role -> liste de DN membres ajoutés PENDANT CETTE EXÉCUTION (séparés par ';')
    > "$USERS_FILE"
    USER_COUNT=0

    echo "    Rôles suggérés (alignés sur les constantes RBAC Go internal.RoleAdmin/"
    echo "    RoleProfessor/RoleStudent) : admin, professeurs, etudiants — mais vous"
    echo "    pouvez saisir n'importe quel nom de rôle."
    echo ""

    while true; do
        read -r -p "    Ajouter un utilisateur pour ${ORG_NAME} ? (o/n) [o]: " ADD_USER
        ADD_USER=${ADD_USER:-o}
        case "$ADD_USER" in
            [oOyY]) ;;
            *) break ;;
        esac

        UID_NAME=""
        while [ -z "$UID_NAME" ]; do
            read -r -p "      uid (identifiant, ex: prof1.${ORG_NAME}) : " UID_NAME
            [ -z "$UID_NAME" ] && echo "      L'uid ne peut pas être vide."
        done

        read -r -p "      Rôle [etudiants] : " ROLE
        ROLE=${ROLE:-etudiants}

        PASSWORD=$(prompt_password)

        HASHED_PW=$(ssha_hash "$PASSWORD")
        unset PASSWORD
        USER_DN="uid=${UID_NAME},ou=users,${BASE_DN}"

        cat << EOF >> "$USERS_FILE"
dn: ${USER_DN}
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: ${UID_NAME}
sn: ${UID_NAME}
uid: ${UID_NAME}
businessCategory: ${ROLE}
userPassword: ${HASHED_PW}

EOF

        if [ -n "${ROLE_MEMBERS[$ROLE]:-}" ]; then
            ROLE_MEMBERS[$ROLE]="${ROLE_MEMBERS[$ROLE]};${USER_DN}"
        else
            ROLE_MEMBERS[$ROLE]="${USER_DN}"
        fi

        USER_COUNT=$((USER_COUNT + 1))
        echo "      ✓ ${UID_NAME} ajouté (rôle: ${ROLE})"
        echo ""
    done

    # --- 02-groups-init.ldif : squelette du groupe (SANS membres) ---
    #     Un seul `dn:` par rôle rencontré, sans attribut `member:`.
    #     À charger avec `ldapadd -c` (continue-on-error) : si le
    #     groupe existe déjà d'une exécution précédente, LDAP renvoie
    #     "Already exists" pour CETTE entrée seulement, ce qui est
    #     normal et sans conséquence.
    #     NB: objectClass groupOfNames exige au moins un `member:` ;
    #     on utilise donc un DN sentinelle vide (la racine LDAP) comme
    #     membre initial, remplacé ensuite par les vrais membres via
    #     02-groups-add-members.ldif.
    > "$GROUPS_INIT_FILE"
    for ROLE in "${!ROLE_MEMBERS[@]}"; do
        {
            echo "dn: cn=${ROLE},ou=groups,${BASE_DN}"
            echo "objectClass: groupOfNames"
            echo "objectClass: top"
            echo "cn: ${ROLE}"
            echo "member: cn=admin,${BASE_DN}"
            echo ""
        } >> "$GROUPS_INIT_FILE"
    done

    # --- 02-groups-add-members.ldif : AJOUT des membres de CETTE exécution ---
    #     `changetype: modify` + `add: member` : s'applique avec
    #     `ldapmodify`, qui AJOUTE au groupe existant au lieu de le
    #     remplacer. C'est ce qui corrige le bug "le rôle ne compte
    #     pas la 2e fois" : chaque exécution n'ajoute que les NOUVEAUX
    #     membres, sans jamais réécrire tout le groupe.
    > "$GROUPS_ADD_MEMBERS_FILE"
    for ROLE in "${!ROLE_MEMBERS[@]}"; do
        {
            echo "dn: cn=${ROLE},ou=groups,${BASE_DN}"
            echo "changetype: modify"
            echo "add: member"
            IFS=';' read -ra MEMBER_ARRAY <<< "${ROLE_MEMBERS[$ROLE]}"
            for MEMBER_DN in "${MEMBER_ARRAY[@]}"; do
                echo "member: ${MEMBER_DN}"
            done
            echo ""
        } >> "$GROUPS_ADD_MEMBERS_FILE"
    done
    unset ROLE_MEMBERS

    echo "    ✓ ${STRUCT_FILE}"
    echo "    ✓ ${GROUPS_INIT_FILE}  (squelettes de groupe, à charger une seule fois par groupe)"
    echo "    ✓ ${GROUPS_ADD_MEMBERS_FILE}  (nouveaux membres de cette exécution uniquement)"
    echo "    ✓ ${USERS_FILE}   (${USER_COUNT} utilisateur(s), mots de passe SSHA)"
    PROCESSED_ORGS+=("${ORG_NAME}|${BASE_DN}")
    echo ""
done

echo "================================================================="
echo "✅ Terminé. Les LDIF sont prêts dans ${FABRIC_CA_DIR}/<org>/ldap-bootstrap/"
echo "   Ils seront chargés automatiquement au (re)démarrage des conteneurs"
echo "   ldap.<org> définis par generate-network.sh / docker-compose.yaml,"
echo "   UNIQUEMENT au tout premier démarrage d'un volume vide."
echo "   (si les conteneurs LDAP existent déjà avec des volumes persistants,"
echo "    utilisez les commandes ci-dessous pour charger les LDIF, ou"
echo "    supprimez les volumes ldapdata.<org>/ldapconfig.<org> pour forcer"
echo "    un rechargement complet depuis zéro)"
echo "================================================================="

if [ "${#PROCESSED_ORGS[@]}" -gt 0 ]; then
    echo ""
    echo "================================================================="
    echo "📋 COMMANDES À LANCER MANUELLEMENT, UNE FOIS LE(S) CONTENEUR(S)"
    echo "   LDAP DÉMARRÉS (ex: docker compose up -d) :"
    echo "   Ordre important : structure -> users -> groups-init -> add-members"
    echo "================================================================="
    for ENTRY in "${PROCESSED_ORGS[@]}"; do
        P_ORG="${ENTRY%%|*}"
        P_DN="${ENTRY##*|}"
        LDAP_DIR="${FABRIC_CA_DIR}/${P_ORG}/ldap-bootstrap"
        echo ""
        echo "# --- ${P_ORG} ---"
        echo "# 1) Structure (ou=users, ou=groups) — ignorez 'Already exists' si déjà chargée"
        echo "ldapadd -x -c -H ldap://localhost:1390 \\"
        echo "  -D \"cn=admin,${P_DN}\" -w ldapadminpw \\"
        echo "  -f ${LDAP_DIR}/01-structure.ldif"
        echo ""
        echo "# 2) Utilisateurs"
        echo "ldapadd -x -c -H ldap://localhost:1390 \\"
        echo "  -D \"cn=admin,${P_DN}\" -w ldapadminpw \\"
        echo "  -f ${LDAP_DIR}/03-users.ldif"
        echo ""
        echo "# 3) Squelettes de groupes — ignorez 'Already exists' si déjà créés"
        echo "ldapadd -x -c -H ldap://localhost:1390 \\"
        echo "  -D \"cn=admin,${P_DN}\" -w ldapadminpw \\"
        echo "  -f ${LDAP_DIR}/02-groups-init.ldif"
        echo ""
        echo "# 4) Ajout des nouveaux membres aux groupes (AJOUTE, ne remplace pas)"
        echo "ldapmodify -x -c -H ldap://localhost:1390 \\"
        echo "  -D \"cn=admin,${P_DN}\" -w ldapadminpw \\"
        echo "  -f ${LDAP_DIR}/02-groups-add-members.ldif"
    done
    echo ""
    echo "================================================================="
fi