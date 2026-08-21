#!/usr/bin/env bash
#
# Build a C++ program against the in-tree fabric-gateway-cpp SDK.
#
#   ./examples/build.sh examples/hello_gateway.cpp
#
# Produces build/third_party/fabric-gateway-cpp/<name> and reuses the exact
# link line already used for the project's live client (so gRPC/protobuf/
# abseil/openssl transitive deps are wired correctly without hand-tuning).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$REPO/build/third_party/fabric-gateway-cpp"

SRC="${1:?usage: build.sh path/to/your.cpp}"
NAME="$(basename "${SRC%.cpp}")"
OBJ="/tmp/opencode/${NAME}.o"
OUT="$BUILD/$NAME"

INCLUDES="-I$REPO/third_party/fabric-gateway-cpp/include -I$BUILD/generated"

echo "Compiling $SRC ..."
c++ -std=c++17 -Wall $INCLUDES -c "$SRC" -o "$OBJ"

LINK="$(tr '\n' ' ' < \
  "$BUILD/CMakeFiles/fabric_gateway_cpp_live_client.dir/link.txt")"
LINK="$(echo "$LINK" | \
  sed "s|CMakeFiles/fabric_gateway_cpp_live_client.dir/tests/live_gateway_client.cpp.o|$OBJ|")"
LINK="$(echo "$LINK" | \
  sed "s|-o fabric_gateway_cpp_live_client|-o $OUT|")"

echo "Linking $OUT ..."
( cd "$BUILD" && eval "$LINK" )

echo "Built: $OUT"
