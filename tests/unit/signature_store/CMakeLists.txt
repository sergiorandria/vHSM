# Signature Store Unit Tests

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/build)

add_executable(vhsm_signature_store_test
    db_tests.cpp
    sqlite_connection_tests.cpp
    sqlite_transaction_tests.cpp
    signature_repository_test.cpp
    signature_store_core_test.cpp
)

target_include_directories(vhsm_signature_store_test
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/signature_store
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/keystore
)

target_link_libraries(vhsm_signature_store_test
    PRIVATE
        vhsm_core
        vhsm_signature_store
        vhsm_keystore
        vhsm_notification
        vhsm_ledger
        GTest::gtest
        GTest::gtest_main
        sqlite3
        pthread
)

# Disable some warnings for test build
target_compile_options(vhsm_signature_store_test PRIVATE -O1 -g -Wno-self-move -Wno-format-truncation)

# Add test to enable testing
include(GoogleTest)
gtest_discover_tests(vhsm_signature_store_test)
