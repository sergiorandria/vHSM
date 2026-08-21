cmake_minimum_required(VERSION 3.21)
project(fabric-gateway-cpp LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find libcurl
find_package(CURL REQUIRED)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Find nlohmann_json
find_package(nlohmann_json 3.2.0 REQUIRED)

# gRPC + protobuf for the peer/gateway/orderer transport layer
find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_program(PROTOC_EXECUTABLE protoc REQUIRED)
find_program(GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin REQUIRED)

# Testing (BUILD_TESTING off by default unless CTest is included)
include(CTest)

# Header locations
set(FABRIC_SDK_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(FABRIC_PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/proto)
set(FABRIC_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${FABRIC_GENERATED_DIR})

# ─────────────────────────────────────────────────────────────────────────────
# Generated gRPC stubs from the vendored fabric-protos snapshot.
# All protos are compiled so that the gateway/deliver services and every
# transitively-imported message type have generated C++ headers.
# ─────────────────────────────────────────────────────────────────────────────

file(GLOB_RECURSE FABRIC_PROTO_PROTOS
     RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}/proto
     ${CMAKE_CURRENT_SOURCE_DIR}/proto/*.proto)
list(SORT FABRIC_PROTO_PROTOS)

# Static library of generated protobuf/gRPC stubs.  Generated code is compiled
# with warnings suppressed regardless of the caller's -Werror flags.
add_library(fabric-proto STATIC)
target_include_directories(fabric-proto PUBLIC ${FABRIC_GENERATED_DIR})
target_include_directories(fabric-proto SYSTEM PRIVATE ${FABRIC_PROTO_DIR})
target_compile_options(fabric-proto PRIVATE -w)

set(FABRIC_PROTO_GENERATED_SRCS)
foreach(proto_rel IN LISTS FABRIC_PROTO_PROTOS)
    get_filename_component(proto_stem ${proto_rel} NAME_WE)
    get_filename_component(proto_dir ${proto_rel} DIRECTORY)
    set(pb_src   ${FABRIC_GENERATED_DIR}/${proto_dir}/${proto_stem}.pb.cc)
    set(pb_hdr   ${FABRIC_GENERATED_DIR}/${proto_dir}/${proto_stem}.pb.h)
    set(grpc_src ${FABRIC_GENERATED_DIR}/${proto_dir}/${proto_stem}.grpc.pb.cc)
    set(grpc_hdr ${FABRIC_GENERATED_DIR}/${proto_dir}/${proto_stem}.grpc.pb.h)

    add_custom_command(
        OUTPUT ${pb_src} ${pb_hdr}
        COMMAND ${PROTOC_EXECUTABLE}
                -I ${FABRIC_PROTO_DIR}
                --cpp_out=${FABRIC_GENERATED_DIR}
                ${CMAKE_CURRENT_SOURCE_DIR}/proto/${proto_rel}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/proto/${proto_rel}
        COMMENT "protoc: ${proto_rel}"
        VERBATIM)
    list(APPEND FABRIC_PROTO_GENERATED_SRCS ${pb_src} ${pb_hdr})
endforeach()

# Generate the gRPC service stubs (Gateway, Deliverer, AtomicBroadcast).  The
# plugin emits per-file sources; protoc resolves cross-file message references
# from the already-generated C++ headers.
add_custom_command(
    OUTPUT
        ${FABRIC_GENERATED_DIR}/gateway/gateway.grpc.pb.cc
        ${FABRIC_GENERATED_DIR}/gateway/gateway.grpc.pb.h
        ${FABRIC_GENERATED_DIR}/peer/events.grpc.pb.cc
        ${FABRIC_GENERATED_DIR}/peer/events.grpc.pb.h
        ${FABRIC_GENERATED_DIR}/orderer/ab.grpc.pb.cc
        ${FABRIC_GENERATED_DIR}/orderer/ab.grpc.pb.h
    COMMAND ${PROTOC_EXECUTABLE}
            -I ${FABRIC_PROTO_DIR}
            --grpc_out=${FABRIC_GENERATED_DIR}
            --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_EXECUTABLE}
            gateway/gateway.proto
            peer/events.proto
            orderer/ab.proto
    DEPENDS
        ${FABRIC_GENERATED_DIR}/gateway/gateway.pb.cc
        ${FABRIC_GENERATED_DIR}/peer/events.pb.cc
        ${FABRIC_GENERATED_DIR}/orderer/ab.pb.cc
        ${CMAKE_CURRENT_SOURCE_DIR}/proto/gateway/gateway.proto
        ${CMAKE_CURRENT_SOURCE_DIR}/proto/peer/events.proto
        ${CMAKE_CURRENT_SOURCE_DIR}/proto/orderer/ab.proto
    COMMENT "protoc: gateway/events/ab (gRPC stubs)"
    VERBATIM)

target_sources(fabric-proto PRIVATE ${FABRIC_PROTO_GENERATED_SRCS}
    ${FABRIC_GENERATED_DIR}/gateway/gateway.grpc.pb.cc
    ${FABRIC_GENERATED_DIR}/gateway/gateway.grpc.pb.h
    ${FABRIC_GENERATED_DIR}/peer/events.grpc.pb.cc
    ${FABRIC_GENERATED_DIR}/peer/events.grpc.pb.h
    ${FABRIC_GENERATED_DIR}/orderer/ab.grpc.pb.cc
    ${FABRIC_GENERATED_DIR}/orderer/ab.grpc.pb.h)
target_link_libraries(fabric-proto PUBLIC protobuf::libprotobuf gRPC::grpc++ gRPC::grpc)

# Library sources — the src/fabric tree is the canonical implementation.
set(SOURCES
    src/fabric/crypto/ec.cpp
    src/fabric/crypto/csr.cpp
    src/fabric/crypto/hash.cpp
    src/fabric/crypto/x509.cpp
    src/fabric/identity/wallet.cpp
    src/fabric/identity/identity.cpp
    src/fabric/ca/httpclient.cpp
    src/fabric/ca/ca_client.cpp
    src/fabric/grpc/grpc_connection.cpp
    src/fabric/grpc/grpc_status.cpp
    src/fabric/protoutil/proposal_builder.cpp
    src/fabric/gateway/gateway.cpp
    src/fabric/gateway/network.cpp
    src/fabric/gateway/contract.cpp
    src/fabric/gateway/transaction.cpp
)

# Create library
add_library(fabric-gateway-cpp STATIC ${SOURCES})

target_include_directories(fabric-gateway-cpp
    PUBLIC  ${FABRIC_SDK_INCLUDE_DIR}
)

# ec.cpp uses the pre-OpenSSL-3 ECDSA_* API for legacy-compat signing;
# silence the deprecation warnings so the SDK builds -Werror-clean.
target_compile_definitions(fabric-gateway-cpp PRIVATE OPENSSL_SUPPRESS_DEPRECATED)

# Link libraries
target_link_libraries(fabric-gateway-cpp
    PUBLIC
        CURL::libcurl
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
        fabric-proto
        gRPC::grpc++
        gRPC::grpc
)

# Install headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION include)
install(TARGETS fabric-gateway-cpp DESTINATION lib)

if(BUILD_TESTING)
    # Phase 1 unit tests: keygen, CSR, sign/verify round-trip, identity, wallet
    find_package(GTest REQUIRED)
    add_executable(fabric_gateway_cpp_unit_tests tests/test_crypto.cpp)
    target_include_directories(fabric_gateway_cpp_unit_tests PRIVATE ${FABRIC_SDK_INCLUDE_DIR})
    target_link_libraries(fabric_gateway_cpp_unit_tests PRIVATE fabric-gateway-cpp GTest::gtest_main)
    add_test(NAME fabric_gateway_cpp_unit_tests COMMAND fabric_gateway_cpp_unit_tests)

    # Phase 2 unit + integration tests: CaClient against a scripted or real CA.
    # The test target itself uses OpenSSL to independently verify CA tokens.
    find_package(OpenSSL REQUIRED)
    add_executable(fabric_gateway_cpp_ca_tests tests/test_ca_client.cpp)
    target_include_directories(fabric_gateway_cpp_ca_tests PRIVATE ${FABRIC_SDK_INCLUDE_DIR})
    target_compile_definitions(fabric_gateway_cpp_ca_tests PRIVATE OPENSSL_SUPPRESS_DEPRECATED)
    target_link_libraries(fabric_gateway_cpp_ca_tests PRIVATE fabric-gateway-cpp GTest::gtest_main OpenSSL::Crypto OpenSSL::SSL)
    add_test(NAME fabric_gateway_cpp_ca_tests COMMAND fabric_gateway_cpp_ca_tests)

    # Phase 3 gRPC transport tests: local echo server exercising
    # GrpcConnection (insecure + TLS + hostname override) and status mapping.
    find_package(Protobuf CONFIG REQUIRED)
    find_package(gRPC CONFIG REQUIRED)
    set(ECHO_PROTO tests/echo.proto)
    set(ECHO_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/testgen)
    file(MAKE_DIRECTORY ${ECHO_GEN_DIR})
    set(echo_pb_src   ${ECHO_GEN_DIR}/echo.pb.cc)
    set(echo_pb_hdr   ${ECHO_GEN_DIR}/echo.pb.h)
    set(echo_grpc_src ${ECHO_GEN_DIR}/echo.grpc.pb.cc)
    set(echo_grpc_hdr ${ECHO_GEN_DIR}/echo.grpc.pb.h)
    add_custom_command(
        OUTPUT ${echo_pb_src} ${echo_pb_hdr} ${echo_grpc_src} ${echo_grpc_hdr}
        COMMAND ${PROTOC_EXECUTABLE}
                -I ${CMAKE_CURRENT_SOURCE_DIR}/tests
                --cpp_out=${ECHO_GEN_DIR}
                --grpc_out=${ECHO_GEN_DIR}
                --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_EXECUTABLE}
                echo.proto
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${ECHO_PROTO}
        COMMENT "protoc: echo.proto"
        VERBATIM)
    add_library(fabric_gateway_cpp_echo STATIC ${echo_pb_src} ${echo_grpc_src} ${echo_pb_hdr} ${echo_grpc_hdr})
    target_include_directories(fabric_gateway_cpp_echo PUBLIC ${ECHO_GEN_DIR})
    target_compile_options(fabric_gateway_cpp_echo PRIVATE -w)
    target_link_libraries(fabric_gateway_cpp_echo PUBLIC protobuf::libprotobuf gRPC::grpc++)

    add_executable(fabric_gateway_cpp_grpc_tests tests/test_grpc.cpp)
    target_include_directories(fabric_gateway_cpp_grpc_tests PRIVATE ${FABRIC_SDK_INCLUDE_DIR})
    target_compile_definitions(fabric_gateway_cpp_grpc_tests PRIVATE OPENSSL_SUPPRESS_DEPRECATED)
    target_link_libraries(fabric_gateway_cpp_grpc_tests PRIVATE fabric-gateway-cpp fabric_gateway_cpp_echo GTest::gtest_main OpenSSL::Crypto OpenSSL::SSL)
    add_test(NAME fabric_gateway_cpp_grpc_tests COMMAND fabric_gateway_cpp_grpc_tests)

    # Phase 4 Gateway client tests: Evaluate / Endorse / Submit / CommitStatus
    # against an in-process fake Gateway service.
    add_executable(fabric_gateway_cpp_gateway_tests tests/test_gateway.cpp)
    target_include_directories(fabric_gateway_cpp_gateway_tests PRIVATE ${FABRIC_SDK_INCLUDE_DIR})
    target_compile_definitions(fabric_gateway_cpp_gateway_tests PRIVATE OPENSSL_SUPPRESS_DEPRECATED)
    target_link_libraries(fabric_gateway_cpp_gateway_tests PRIVATE fabric-gateway-cpp GTest::gtest_main OpenSSL::Crypto OpenSSL::SSL)
    add_test(NAME fabric_gateway_cpp_gateway_tests COMMAND fabric_gateway_cpp_gateway_tests)

    # vHSM live-network Gateway client: connects to a real Fabric peer over
    # TLS and evaluates a chaincode transaction (see file header for usage).
    add_executable(fabric_gateway_cpp_live_client tests/live_gateway_client.cpp)
    target_include_directories(fabric_gateway_cpp_live_client PRIVATE ${FABRIC_SDK_INCLUDE_DIR})
    target_compile_definitions(fabric_gateway_cpp_live_client PRIVATE OPENSSL_SUPPRESS_DEPRECATED)
    target_link_libraries(fabric_gateway_cpp_live_client PRIVATE fabric-gateway-cpp OpenSSL::Crypto OpenSSL::SSL)
endif()