add_library(vhsm_signature_store)

target_sources(vhsm_signature_store
    PRIVATE
    db_schema.cpp
    db_row.cpp
    db_connection.cpp
    sqlite_connection.cpp
    sqlite_transaction.cpp
    sqlite_helpers.cpp
)

target_include_directories(vhsm_signature_store
    PUBLIC ${PROJECT_SOURCE_DIR}
)

target_link_libraries(vhsm_signature_store
    PUBLIC
    vhsm_core
    vhsm_crypto
    vhsm_keystore
    OpenSSL::SSL
)