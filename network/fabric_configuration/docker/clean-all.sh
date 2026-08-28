#!/usr/bin/env bash
# Wrapper for the Fabric network clean — delegates to docker/clean.sh
# Usage: ./clean-all.sh [--yes] [--keep-images]

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/clean.sh" "$@"
