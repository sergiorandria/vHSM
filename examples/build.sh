#!/usr/bin/env bash
#
# Build one or all C++ examples against the in-tree fabric-gateway-cpp SDK.
#
#   ./examples/build.sh                 # builds every examples/*.cpp
#   ./examples/build.sh hello_gateway   # builds a single example by name
#
# Output binaries land next to the SDK static libs in
# build/third_party/fabric-gateway-cpp/<name> and reuse the exact link line
# already used for the project's live client (so gRPC/protobuf/abseil/openssl
# transitive deps are wired correctly without hand-tuning).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$REPO/build/third_party/fabric-gateway-cpp"
EXAMPLES="$REPO/examples"
LINKTXT="$BUILD/CMakeFiles/fabric_gateway_cpp_live_client.dir/link.txt"

INCLUDES="-I$REPO/third_party/fabric-gateway-cpp/include -I$BUILD/generated"

build_one() {
  local SRC="$1"
  local NAME="$(basename "${SRC%.cpp}")"
  local OBJ="/tmp/opencode/${NAME}.o"
  local OUT="$BUILD/$NAME"
  echo ">> Compiling $SRC"
  c++ -std=c++23 -Wall $INCLUDES -c "$SRC" -o "$OBJ"
  local LINK="$(tr '\n' ' ' < "$LINKTXT")"
  LINK="$(echo "$LINK" | sed "s|CMakeFiles/fabric_gateway_cpp_live_client.dir/tests/live_gateway_client.cpp.o|$OBJ|")"
  LINK="$(echo "$LINK" | sed "s|-o fabric_gateway_cpp_live_client|-o $OUT|")"
  echo ">> Linking $OUT"
  ( cd "$BUILD" && eval "$LINK" )
  echo "Built: $OUT"
}

if [ "$#" -ge 1 ]; then
  build_one "$EXAMPLES/$1.cpp"
  exit 0
fi

for f in "$EXAMPLES"/*.cpp; do
  build_one "$f"
done
