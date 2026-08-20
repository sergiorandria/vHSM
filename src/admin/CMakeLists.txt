# vHSM admin — gRPC management + signature query API (PLAN.md §9–§10).
#
# This directory builds the HsmAdmin gRPC service: SO/USER authentication,
# token backup/restore, the signature query/verification API, ledger management
# and notification subscriber management.
#
# Proto codegen mirrors the pattern in third_party/fabric-gateway-cpp: protoc
# emits message stubs and grpc_cpp_plugin emits the service stubs.  Generated
# code is compiled with warnings suppressed (gRPC-generated code is not
# -Werror-clean).

set(ADMIN_PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(ADMIN_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${ADMIN_GENERATED_DIR})

find_program(PROTOC_EXECUTABLE protoc REQUIRED)
find_program(GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin REQUIRED)

set(ADMIN_PB_SRC   ${ADMIN_GENERATED_DIR}/hsm_admin.pb.cc)
set(ADMIN_PB_HDR   ${ADMIN_GENERATED_DIR}/hsm_admin.pb.h)
set(ADMIN_GRPC_SRC ${ADMIN_GENERATED_DIR}/hsm_admin.grpc.pb.cc)
set(ADMIN_GRPC_HDR ${ADMIN_GENERATED_DIR}/hsm_admin.grpc.pb.h)

add_custom_command(
    OUTPUT ${ADMIN_PB_SRC} ${ADMIN_PB_HDR}
    COMMAND ${PROTOC_EXECUTABLE}
            -I ${ADMIN_PROTO_DIR}
            --cpp_out=${ADMIN_GENERATED_DIR}
            ${ADMIN_PROTO_DIR}/hsm_admin.proto
    DEPENDS ${ADMIN_PROTO_DIR}/hsm_admin.proto
    COMMENT "protoc: hsm_admin.proto"
    VERBATIM)

add_custom_command(
    OUTPUT ${ADMIN_GRPC_SRC} ${ADMIN_GRPC_HDR}
    COMMAND ${PROTOC_EXECUTABLE}
            -I ${ADMIN_PROTO_DIR}
            --grpc_out=${ADMIN_GENERATED_DIR}
            --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_EXECUTABLE}
            ${ADMIN_PROTO_DIR}/hsm_admin.proto
    DEPENDS ${ADMIN_PROTO_DIR}/hsm_admin.proto ${ADMIN_PB_SRC}
    COMMENT "protoc: hsm_admin.proto (gRPC stubs)"
    VERBATIM)

add_library(vhsm_admin STATIC
    admin_service.cpp
    hsm_admin_grpc.cpp
    ${ADMIN_PB_SRC}
    ${ADMIN_GRPC_SRC}
)

target_include_directories(vhsm_admin
    PUBLIC
        ${PROJECT_SOURCE_DIR}
)

# Generated headers live in the build tree; keep -Werror from tripping on them.
target_include_directories(vhsm_admin
    SYSTEM PRIVATE ${ADMIN_GENERATED_DIR}
)

target_compile_options(vhsm_admin PRIVATE -Wno-deprecated-declarations)

target_link_libraries(vhsm_admin
    PUBLIC
        vhsm_core
        vhsm_keystore
        vhsm_persistence
        vhsm_session
        vhsm_notification
        vhsm_signature_store
        protobuf::libprotobuf
        gRPC::grpc++
)