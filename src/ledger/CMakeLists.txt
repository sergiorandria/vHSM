# vHSM ledger anchoring client (Hyperledger Fabric Gateway).
add_library(vhsm_ledger)

target_sources(vhsm_ledger
    PRIVATE
    ledger_client.cpp
    ledger_worker.cpp
)

target_include_directories(vhsm_ledger
    PUBLIC ${PROJECT_SOURCE_DIR}
)

# fabric-gateway-cpp transitively provides the gRPC++, protobuf, OpenSSL and
# generated-proto include paths and link dependencies.
target_link_libraries(vhsm_ledger
    PUBLIC
        fabric-gateway-cpp
        nlohmann_json::nlohmann_json
)
