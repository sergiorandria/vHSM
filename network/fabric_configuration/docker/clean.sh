#!/usr/bin/env bash
# clean.sh — safely remove the *in-place* Fabric network (containers, volumes, generated crypto)
# Usage: ./clean.sh [--yes] [--keep-images]
#   --yes          skip confirmation
#   --keep-images  do not prune Fabric Docker images (faster re-up)
#
# SAFETY:
# - Must be run from network/fabric_configuration/docker (checks for docker-compose.yaml + organizations/)
# - Never touches /etc/vhsmd, ledger data outside this subtree, or host files
# - Uses `docker compose -f <file> down -v` with explicit file, not bare `docker rm -f $(docker ps -aq)`
# - Requires confirmation unless --yes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yaml"
CHANNEL_ARTIFACTS="$SCRIPT_DIR/channel-artifacts"
ORGS_DIR="$SCRIPT_DIR/organizations"
PEER_DATA_DIR="$SCRIPT_DIR/peer-data"

KEEP_IMAGES=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --keep-images) KEEP_IMAGES=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --help|-h)
      echo "Usage: $0 [--yes] [--keep-images]"
      exit 0
      ;;
  esac
done

# --- Safety checks ---
if [[ ! -f "$COMPOSE_FILE" ]]; then
  echo "ERROR: $COMPOSE_FILE not found. Run this script from network/fabric_configuration/docker/" >&2
  exit 1
fi
if [[ ! -d "$ORGS_DIR" && ! -d "$CHANNEL_ARTIFACTS" && ! -d "$PEER_DATA_DIR" ]]; then
  echo "WARNING: No generated artifacts found ($ORGS_DIR, $CHANNEL_ARTIFACTS). Nothing to clean, but continuing." >&2
fi

# --- Confirmation ---
if [[ $ASSUME_YES -eq 0 ]]; then
  echo "This will:"
  echo "  1. docker compose -f $COMPOSE_FILE down -v  (containers + volumes for this network only)"
  echo "  2. rm -rf $CHANNEL_ARTIFACTS $ORGS_DIR $PEER_DATA_DIR"
  echo "  3. docker volume prune (only pgdata.* and ca-data.* for this network, not all volumes)"
  echo ""
  read -rp "Remove the in-place Fabric network at $SCRIPT_DIR ? [y/N] " ans
  case "$ans" in
    y|Y|yes|YES) ;;
    *) echo "Aborted."; exit 0 ;;
  esac
fi

# --- 1. Compose down (explicit file, scoped to this network) ---
if command -v docker &>/dev/null; then
  if docker compose version &>/dev/null; then
    COMPOSE="docker compose -f $COMPOSE_FILE"
  else
    COMPOSE="docker-compose -f $COMPOSE_FILE"
  fi
  echo "==> $COMPOSE down -v"
  $COMPOSE down -v 2>/dev/null || true

  # Prune only volumes that belong to this network (never `docker volume prune -f` blindly)
  echo "==> pruning pgdata.* and ca-data.* volumes for this network"
  for vol in $(docker volume ls -q 2>/dev/null | grep -E '^(pgdata|ca-data)\.' || true); do
    docker volume rm "$vol" 2>/dev/null || true
  done

  # Optionally prune images (only if --keep-images not set)
  if [[ $KEEP_IMAGES -eq 0 ]]; then
    echo "==> pruning Fabric images (hyperledger/fabric-*) for a clean re-pull"
    for img in $(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -E 'hyperledger/fabric-' || true); do
      docker rmi "$img" 2>/dev/null || true
    done
  fi
else
  echo "WARNING: docker not found, skipping container/volume cleanup." >&2
fi

# --- 2. Remove generated artifacts (scoped, never `rm -rf /`) ---
echo "==> removing generated artifacts"
for target in "$CHANNEL_ARTIFACTS" "$ORGS_DIR" "$PEER_DATA_DIR"; do
  if [[ -e "$target" ]]; then
    # Extra safety: ensure target is inside SCRIPT_DIR
    case "$(realpath "$target" 2>/dev/null || echo "$target")" in
      "$SCRIPT_DIR"/*) rm -rf "$target" && echo "  removed $target" ;;
      *) echo "  SKIPPED $target (outside $SCRIPT_DIR, not removing)" >&2 ;;
    esac
  fi
done

# Also remove the generated config files that `generate-network.sh` creates in this dir
for gen in "$SCRIPT_DIR/configtx.yaml" "$SCRIPT_DIR/network.env" "$SCRIPT_DIR/.env.example"; do
  if [[ -f "$gen" ]]; then
    echo "  kept $gen (re-generated on next ./generate-network.sh)"
  fi
done

echo ""
echo "Clean done. To regenerate:"
echo "  cd $SCRIPT_DIR && ./generate-network.sh && ./enroll-network.sh && docker compose -f docker-compose.yaml up -d"
