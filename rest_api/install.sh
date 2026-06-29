#!/usr/bin/env bash
# =============================================================================
# install.sh — electronic_signature / vHSM service installer
# Interactive: prompts for all credentials, auto-configures HSM + MinIO,
# then writes a ready-to-source environment file for the Go API.
#
# Supports: Debian/Ubuntu (apt) · RHEL/Fedora/CentOS (dnf/yum) · Arch (pacman)
# Run as root or with sudo.
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Colours & helpers
# ─────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
header()  { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }

require_root() {
    [[ $EUID -eq 0 ]] || error "Run as root or with sudo."
}

# Prompt with a default value shown in brackets
# Usage: prompt_default VARNAME "Question" "default"
prompt_default() {
    local var="$1" question="$2" default="$3"
    echo -ne "${BOLD}${question}${NC} [${CYAN}${default}${NC}]: "
    read -r input
    printf -v "$var" '%s' "${input:-$default}"
}

# Prompt for a secret (no echo), with a generated default shown as hint
# Usage: prompt_secret VARNAME "Question" "default"
prompt_secret() {
    local var="$1" question="$2" default="$3"
    echo -ne "${BOLD}${question}${NC} [leave blank for auto-generated]: "
    read -rs input
    echo
    if [[ -z "$input" ]]; then
        printf -v "$var" '%s' "$default"
        info "Auto-generated value will be used."
    else
        printf -v "$var" '%s' "$input"
    fi
}

# Generate a random alphanumeric string of given length
rand_str() { tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "${1:-16}"; }

# ─────────────────────────────────────────────────────────────────────────────
# Architecture detection
# ─────────────────────────────────────────────────────────────────────────────
detect_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)          ARCH_LABEL="amd64" ;;
        aarch64|arm64)   ARCH_LABEL="arm64" ;;
        armv7l)          ARCH_LABEL="armv7" ;;
        *) error "Unsupported architecture: $ARCH" ;;
    esac
    info "Architecture: $ARCH → $ARCH_LABEL"
}

# ─────────────────────────────────────────────────────────────────────────────
# Package manager detection
# ─────────────────────────────────────────────────────────────────────────────
detect_pkg_manager() {
    if   command -v apt-get &>/dev/null; then PKG_MANAGER="apt"
    elif command -v dnf     &>/dev/null; then PKG_MANAGER="dnf"
    elif command -v yum     &>/dev/null; then PKG_MANAGER="yum"
    elif command -v pacman  &>/dev/null; then PKG_MANAGER="pacman"
    else error "No supported package manager found (apt/dnf/yum/pacman)."
    fi
    info "Package manager: $PKG_MANAGER"
}

pkg_install() {
    case "$PKG_MANAGER" in
        apt)    apt-get update -qq
                DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
        dnf)    dnf install -y "$@" ;;
        yum)    yum install -y "$@" ;;
        pacman) pacman -Sy --noconfirm "$@" ;;
    esac
}

install_deps() {
    header "Installing system dependencies"
    case "$PKG_MANAGER" in
        apt)
            pkg_install curl wget gnupg2 ca-certificates \
                softhsm2 opensc libengine-pkcs11-openssl \
                p11-kit p11-kit-modules
            ;;
        dnf|yum)
            pkg_install curl wget gnupg2 ca-certificates \
                softhsm opensc p11-kit p11-kit-trust
            ;;
        pacman)
            pkg_install curl wget gnupg softhsm opensc p11-kit
            ;;
    esac
    success "Dependencies installed."
}

# ─────────────────────────────────────────────────────────────────────────────
# Interactive prompts — collect all config up front
# ─────────────────────────────────────────────────────────────────────────────
collect_config() {
    echo -e "\n${BOLD}${GREEN}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║      vHSM / electronic_signature  —  Installer      ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo "  Answer the prompts below. Press Enter to accept the"
    echo "  value shown in [brackets]."
    echo

    # ── HSM ──────────────────────────────────────────────────
    header "SoftHSM2 token"
    prompt_default HSM_TOKEN_LABEL "Token label"          "vhsm-token"
    prompt_secret  HSM_SO_PIN      "Security Officer PIN" "$(rand_str 16)"
    prompt_secret  HSM_PIN         "User PIN"             "$(rand_str 16)"
    prompt_default HSM_KEY_LABEL   "AES key label"        "vhsm-aes-key"

    # ── MinIO ─────────────────────────────────────────────────
    header "MinIO object storage"
    prompt_default MINIO_PORT         "MinIO API port"     "9000"
    prompt_default MINIO_CONSOLE_PORT "MinIO console port" "9001"
    prompt_default MINIO_BUCKET       "Default bucket"     "thesis"
    prompt_default MINIO_ACCESS_KEY   "Root user"          "minioadmin"
    prompt_secret  MINIO_SECRET_KEY   "Root password"      "$(rand_str 20)"

    # ── Fabric ────────────────────────────────────────────────
    header "Hyperledger Fabric gateway"
    prompt_default FABRIC_MSP_ID      "MSP ID"           "Org1MSP"
    prompt_default FABRIC_CHANNEL     "Channel name"     "mychannel"
    prompt_default FABRIC_CHAINCODE   "Chaincode name"   "jurychaincode"
    prompt_default FABRIC_CRYPTO_PATH "Crypto path"      "/etc/vhsmd/crypto"
    prompt_default FABRIC_PEER_EP     "Peer endpoint"    "127.0.0.1:7051"
    prompt_default FABRIC_PEER_NAME   "Gateway peer name" "peer0.org1.example.com"

    # ── API ───────────────────────────────────────────────────
    header "Go API"
    prompt_default API_PORT "Listening port" "8080"

    echo
    echo -e "${YELLOW}Configuration collected. Starting installation…${NC}"
    echo
}

# ─────────────────────────────────────────────────────────────────────────────
# SoftHSM2 — init token, detect slot, generate AES key
# ─────────────────────────────────────────────────────────────────────────────
SOFTHSM2_CONF="/etc/softhsm2.conf"
SOFTHSM2_TOKEN_DIR="/var/lib/softhsm/tokens"

init_softhsm() {
    header "SoftHSM2 initialisation"

    mkdir -p "$SOFTHSM2_TOKEN_DIR"
    chmod 750 "$SOFTHSM2_TOKEN_DIR"

    if [[ ! -f "$SOFTHSM2_CONF" ]]; then
        cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = ${SOFTHSM2_TOKEN_DIR}
objectstore.backend = file
log.level = ERROR
slots.removable = false
EOF
        success "SoftHSM2 config → $SOFTHSM2_CONF"
    else
        warn "SoftHSM2 config already exists — keeping."
    fi

    # Wipe any existing token with our label to avoid PIN mismatch on reinstall
    if softhsm2-util --show-slots 2>/dev/null | grep -q "Label:[[:space:]]*${HSM_TOKEN_LABEL}"; then
        warn "Existing token '${HSM_TOKEN_LABEL}' found — wiping for clean reinstall."
        local existing_slot
        existing_slot=$(softhsm2-util --show-slots 2>/dev/null | awk -v label="$HSM_TOKEN_LABEL" '
            /^Slot [0-9]+/ { slot=$2 }
            /Label:/ && index($0, label) { print slot; exit }
        ')
        softhsm2-util --delete-token --slot "$existing_slot" 2>/dev/null \
            && success "Old token in slot $existing_slot deleted." \
            || warn    "Could not delete old token — continuing anyway."
    fi

    softhsm2-util --init-token --free \
        --label  "$HSM_TOKEN_LABEL" \
        --so-pin "$HSM_SO_PIN"      \
        --pin    "$HSM_PIN"
    success "Token '${HSM_TOKEN_LABEL}' initialised."

    # ── Auto-detect slot number assigned to our token ────────────
    # softhsm2-util --show-slots output contains blocks like:
    #   Slot N
    #       ...
    #       Label:   <label>
    # We parse it with awk: when we see "Slot N" we record N;
    # when we see our label we print the last recorded slot number.
    HSM_SLOT=$(softhsm2-util --show-slots 2>/dev/null | awk -v label="$HSM_TOKEN_LABEL" '
        /^Slot [0-9]+/ { slot=$2 }
        /Label:/ && index($0, label) { print slot; exit }
    ')

    if [[ -z "$HSM_SLOT" ]]; then
        # Fallback: use slot 0 if awk found nothing (fresh single-token install)
        HSM_SLOT=0
        warn "Could not auto-detect slot — defaulting to slot 0."
    fi
    success "Token slot: $HSM_SLOT"

    # ── Auto-detect PKCS#11 module path ─────────────────────────
    SOFTHSM2_MODULE=""
    for candidate in \
        /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib64/softhsm/libsofthsm2.so \
        /usr/lib/libsofthsm2.so; do
        [[ -f "$candidate" ]] && { SOFTHSM2_MODULE="$candidate"; break; }
    done
    [[ -n "$SOFTHSM2_MODULE" ]] || error "libsofthsm2.so not found — check installation."
    success "PKCS#11 module: $SOFTHSM2_MODULE"

    # ── Generate AES-256 key inside the token if absent ─────────
    if pkcs11-tool --module "$SOFTHSM2_MODULE" \
            --slot "$HSM_SLOT" --pin "$HSM_PIN" \
            --list-objects 2>/dev/null | grep -q "$HSM_KEY_LABEL"; then
        warn "Key '${HSM_KEY_LABEL}' already exists in token — skipping keygen."
    else
        pkcs11-tool --module "$SOFTHSM2_MODULE" \
            --slot "$HSM_SLOT" --pin "$HSM_PIN" \
            --keygen --key-type AES:32 \
            --label "$HSM_KEY_LABEL" \
            --sensitive
        success "AES-256 key '${HSM_KEY_LABEL}' generated in slot $HSM_SLOT."
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# MinIO — install binary, create user, configure systemd
# ─────────────────────────────────────────────────────────────────────────────
MINIO_USER="minio-user"
MINIO_DATA_DIR="/var/lib/minio/data"
MINIO_CONFIG_DIR="/etc/minio"
MINIO_SERVICE_FILE="/etc/systemd/system/minio.service"

install_minio() {
    header "MinIO installation"

    # Download binary if not already present or if broken
    if [[ -x /usr/local/bin/minio ]]; then
        warn "MinIO already installed at /usr/local/bin/minio — skipping download."
    else
        local url
        case "$ARCH_LABEL" in
            amd64) url="https://dl.min.io/server/minio/release/linux-amd64/minio" ;;
            arm64) url="https://dl.min.io/server/minio/release/linux-arm64/minio" ;;
            armv7) url="https://dl.min.io/server/minio/release/linux-arm/minio"   ;;
        esac
        info "Downloading MinIO from $url"
        curl -fSL --progress-bar "$url" -o /usr/local/bin/minio             || error "MinIO download failed. Check network and try again."
        chmod +x /usr/local/bin/minio

        # Sanity-check: the binary must be an ELF executable
        if ! file /usr/local/bin/minio | grep -q "ELF"; then
            rm -f /usr/local/bin/minio
            error "Downloaded file is not a valid ELF binary. Download may have been corrupted."
        fi
        success "MinIO binary → /usr/local/bin/minio"
    fi

    id "$MINIO_USER" &>/dev/null \
        || { useradd -r -s /sbin/nologin -d "$MINIO_DATA_DIR" "$MINIO_USER"
             success "System user '$MINIO_USER' created."; }

    mkdir -p "$MINIO_DATA_DIR" "$MINIO_CONFIG_DIR"
    chown -R "$MINIO_USER":"$MINIO_USER" "$MINIO_DATA_DIR" "$MINIO_CONFIG_DIR"

    # Write MinIO env file (credentials only — no OPTS/VOLUMES here)
    cat > "$MINIO_CONFIG_DIR/minio.env" <<EOF
# Auto-generated by install.sh — $(date -u '+%Y-%m-%dT%H:%M:%SZ')
MINIO_ROOT_USER=${MINIO_ACCESS_KEY}
MINIO_ROOT_PASSWORD=${MINIO_SECRET_KEY}
EOF
    chmod 600 "$MINIO_CONFIG_DIR/minio.env"
    success "MinIO config → $MINIO_CONFIG_DIR/minio.env"

    # Always rewrite the service file so port/path changes take effect
    # NOTE: ExecStart arguments are hardcoded here — systemd does NOT
    # word-split environment variables, so $MINIO_OPTS would be passed
    # as a single argument rather than expanded flags.
    cat > "$MINIO_SERVICE_FILE" <<EOF
[Unit]
Description=MinIO object storage
Documentation=https://min.io/docs/
After=network-online.target
Wants=network-online.target

[Service]
User=${MINIO_USER}
Group=${MINIO_USER}
EnvironmentFile=${MINIO_CONFIG_DIR}/minio.env
ExecStart=/usr/local/bin/minio server \
    --address :${MINIO_PORT} \
    --console-address :${MINIO_CONSOLE_PORT} \
    ${MINIO_DATA_DIR}
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    success "MinIO systemd unit → $MINIO_SERVICE_FILE"

    systemctl daemon-reload
    systemctl enable --now minio
    success "MinIO service enabled and started."

    # Wait up to 15 s for MinIO to become ready
    info "Waiting for MinIO to be ready…"
    for i in $(seq 1 15); do
        if curl -sf "http://127.0.0.1:${MINIO_PORT}/minio/health/live" &>/dev/null; then
            success "MinIO is up."; break
        fi
        sleep 1
        [[ $i -eq 15 ]] && warn "MinIO did not respond in time — check: journalctl -u minio -n 30"
    done

    # Auto-create default bucket using the mc client if available
    if command -v mc &>/dev/null; then
        mc alias set vhsm "http://127.0.0.1:${MINIO_PORT}" \
            "$MINIO_ACCESS_KEY" "$MINIO_SECRET_KEY" &>/dev/null
        mc mb --ignore-existing "vhsm/${MINIO_BUCKET}" &>/dev/null \
            && success "Bucket '${MINIO_BUCKET}' created." \
            || warn    "Could not create bucket — create it manually."
    else
        warn "mc (MinIO client) not installed — bucket '${MINIO_BUCKET}' must be created manually."
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Write /etc/vhsmd/default-fabric.conf  (read by utils.LoadConfig())
# ─────────────────────────────────────────────────────────────────────────────
APP_CONF_DIR="/etc/vhsmd"
FABRIC_CONF="$APP_CONF_DIR/default-fabric.conf"
ENV_FILE="$APP_CONF_DIR/vhsmd.env"

write_fabric_conf() {
    header "Fabric gateway configuration"
    mkdir -p "$APP_CONF_DIR"

    cat > "$FABRIC_CONF" <<EOF
# =============================================================================
# Fabric Gateway — /etc/vhsmd/default-fabric.conf
# Auto-generated by install.sh on $(date -u '+%Y-%m-%dT%H:%M:%SZ')
# Priority: environment variable > this file > binary default
# =============================================================================

MSP_ID=${FABRIC_MSP_ID}
CHANNEL_NAME=${FABRIC_CHANNEL}
CHAINCODE_NAME=${FABRIC_CHAINCODE}

CRYPTO_PATH=${FABRIC_CRYPTO_PATH}

# Paths below use literal \${CRYPTO_PATH} — resolved at runtime by LoadConfig()
CERT_PATH=\${CRYPTO_PATH}/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem
KEY_PATH=\${CRYPTO_PATH}/users/User1@org1.example.com/msp/keystore
TLS_CERT_PATH=\${CRYPTO_PATH}/peers/peer0.org1.example.com/tls/ca.crt

PEER_ENDPOINT=${FABRIC_PEER_EP}
GATEWAY_PEER_NAME=${FABRIC_PEER_NAME}
EOF
    chmod 640 "$FABRIC_CONF"
    success "Fabric config → $FABRIC_CONF"
}

# ─────────────────────────────────────────────────────────────────────────────
# Write /etc/vhsmd/vhsmd.env — source this before running the Go binary
# ─────────────────────────────────────────────────────────────────────────────
write_env_file() {
    header "Service environment file"

    cat > "$ENV_FILE" <<EOF
# =============================================================================
# vHSM service environment — /etc/vhsmd/vhsmd.env
# Auto-generated by install.sh on $(date -u '+%Y-%m-%dT%H:%M:%SZ')
#
# Usage:
#   source /etc/vhsmd/vhsmd.env && ./vhsmd
#   — or —
#   Add  EnvironmentFile=/etc/vhsmd/vhsmd.env  to your systemd unit.
# =============================================================================

# ── HSM ──────────────────────────────────────────────────────────────────────
HSM_MODULE_PATH=${SOFTHSM2_MODULE}
HSM_TOKEN_LABEL=${HSM_TOKEN_LABEL}
HSM_SLOT=${HSM_SLOT}
HSM_PIN=${HSM_PIN}
HSM_LABEL=${HSM_KEY_LABEL}

# ── MinIO ────────────────────────────────────────────────────────────────────
MINIO_ENDPOINT=127.0.0.1:${MINIO_PORT}
MINIO_ACCESS_KEY=${MINIO_ACCESS_KEY}
MINIO_SECRET_KEY=${MINIO_SECRET_KEY}
MINIO_BUCKET=${MINIO_BUCKET}

# ── API ──────────────────────────────────────────────────────────────────────
PORT=${API_PORT}
EOF
    chmod 600 "$ENV_FILE"
    success "Environment file → $ENV_FILE"
}

# ─────────────────────────────────────────────────────────────────────────────
# Final summary
# ─────────────────────────────────────────────────────────────────────────────
print_summary() {
    echo
    echo -e "${GREEN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║               Installation complete ✓                   ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    printf "  %-22s %s\n" "Config dir:"      "$APP_CONF_DIR"
    printf "  %-22s %s\n" "Fabric conf:"     "$FABRIC_CONF"
    printf "  %-22s %s\n" "Env file:"        "$ENV_FILE"
    printf "  %-22s %s\n" "HSM module:"      "$SOFTHSM2_MODULE"
    printf "  %-22s %s\n" "HSM token:"       "$HSM_TOKEN_LABEL  (slot $HSM_SLOT)"
    printf "  %-22s %s\n" "HSM key:"         "$HSM_KEY_LABEL"
    printf "  %-22s %s\n" "MinIO API:"       "http://127.0.0.1:${MINIO_PORT}"
    printf "  %-22s %s\n" "MinIO console:"   "http://127.0.0.1:${MINIO_CONSOLE_PORT}"
    printf "  %-22s %s\n" "MinIO bucket:"    "$MINIO_BUCKET"
    echo
    echo -e "${YELLOW}${BOLD}Next steps:${NC}"
    echo "  1. Copy your Fabric crypto material:"
    echo "       cp -r <your-crypto-path>/* ${FABRIC_CRYPTO_PATH}/"
    echo
    echo "  2. Start the API (environment auto-loaded):"
    echo "       source ${ENV_FILE} && ./vhsmd"
    echo
    echo "  3. Or use a systemd unit with:"
    echo "       EnvironmentFile=${ENV_FILE}"
    echo
    echo -e "${RED}  ⚠  Keep ${ENV_FILE} private — it contains credentials.${NC}"
    echo
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
main() {
    require_root
    detect_arch
    detect_pkg_manager
    collect_config      # interactive — all prompts happen here, before any changes
    install_deps
    init_softhsm
    install_minio
    write_fabric_conf
    write_env_file
    print_summary
}

main "$@"