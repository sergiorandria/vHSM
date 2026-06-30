#!/usr/bin/env bash
# =============================================================================
# tailscale-setup.sh — installs and configures Tailscale for the vHSM
# multi-engineer Fabric network. Run as root or with sudo.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || error "Run as root or with sudo."

# ── 1. Detect package manager & install Tailscale ──────────────────────────
if command -v pacman &>/dev/null; then
    info "Arch detected — installing tailscale via pacman"
    pacman -Sy --noconfirm tailscale
elif command -v apt-get &>/dev/null; then
    info "Debian/Ubuntu detected — installing via official script"
    curl -fsSL https://tailscale.com/install.sh | sh
elif command -v dnf &>/dev/null; then
    info "Fedora/RHEL detected — installing via dnf"
    dnf install -y tailscale
else
    error "Unsupported package manager — install Tailscale manually: https://tailscale.com/download"
fi

# ── 2. Enable and start the daemon ──────────────────────────────────────────
info "Enabling tailscaled service"
systemctl enable --now tailscaled

# ── 3. Optional: enable IP forwarding (needed if this node will act as a
#      subnet router / exit node, e.g. routing Docker's fabric network)
read -p "Will this machine act as a subnet router for Docker/Fabric traffic? (y/N): " SUBNET_ROUTER
if [[ "$SUBNET_ROUTER" =~ ^[Yy]$ ]]; then
    info "Enabling IP forwarding"
    cat <<EOF >> /etc/sysctl.d/99-tailscale.conf
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
    sysctl -p /etc/sysctl.d/99-tailscale.conf
fi

# ── 4. Bring up the interface — THIS STEP NEEDS YOU ─────────────────────────
echo
info "Almost done. Run the following command yourself to join the tailnet:"
echo
echo "    sudo tailscale up --hostname=\$(hostname)"
echo
info "This will print a login URL — open it in your browser and approve the"
info "device under your team's Tailscale account (or join an existing invite)."
echo
info "Once connected, verify with:"
echo "    tailscale status"
echo "    tailscale ip -4"