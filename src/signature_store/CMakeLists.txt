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
    ../audit/audit_log.cpp
    signature_dispatcher.cpp
    signature_query.cpp
    verification_service.cpp
    internal/signature_dispatcher_core.cpp
    internal/signature_query_core.cpp
    internal/verification_service_core.cpp
)

target_include_directories(vhsm_signature_store
    PUBLIC ${PROJECT_SOURCE_DIR}
)

target_link_libraries(vhsm_signature_store
    PUBLIC
    vhsm_core
    vhsm_crypto
    vhsm_keystore
    vhsm_notification
    vhsm_ledger
    OpenSSL::SSL
)