add_library(vhsm_signature_store)

target_sources(vhsm_signature_store
    PRIVATE
    db_schema.cpp
    db_row.cpp
    db_connection.cpp
    sqlite_connection.cpp
    sqlite_transaction.cpp
    sqlite_helpers.cpp
    db_config.h
    db_hmac_key.cpp
    row_integrity.cpp
    signature_repository.cpp
    ledger_retry_queue.cpp
    notification_repository.cpp
    notification_dispatcher.cpp
    ../audit/audit_log.cpp
    signature_dispatcher.cpp
    signature_query.cpp
    verification_service.cpp
    outbox_poller.cpp
    outbox_poller.h
    internal/signature_dispatcher_core.cpp
    internal/signature_query_core.cpp
    internal/verification_service_core.cpp
    ../domain/signing/key_policy.cpp
)

target_include_directories(vhsm_signature_store
    PUBLIC ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(vhsm_signature_store
    PUBLIC
    vhsm_core
    vhsm_crypto
    vhsm_keystore
    vhsm_persistence
    vhsm_notification
    vhsm_metrics
    vhsm_crypto_provider
)

# KeyPolicy JSON (de)serialization uses nlohmann/json; link it when present so
# the policy/attestation engine builds both with and without the ledger enabled.
if(nlohmann_json_FOUND)
    target_link_libraries(vhsm_signature_store PUBLIC nlohmann_json::nlohmann_json)
endif()
if(VHSM_LEDGER)
    target_link_libraries(vhsm_signature_store PUBLIC vhsm_ledger)
endif()