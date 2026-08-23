#!/usr/bin/env bash
# Wrapper for the Fabric network clean — delegates to fabric-network/clean.sh
# Usage: ./network/clean.sh [--yes] [--keep-images]

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/fabric_configuration/fabric-network/clean.sh" "$@"
