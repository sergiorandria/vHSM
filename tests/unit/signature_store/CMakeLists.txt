# Signature Store Unit Tests

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/unit/signature_store)

add_executable(vhsm_signature_store_test
    db_tests.cpp
    sqlite_connection_tests.cpp
    sqlite_transaction_tests.cpp
    signature_repository_test.cpp
    notification_dispatcher_test.cpp
)
if(VHSM_LEDGER)
    target_sources(vhsm_signature_store_test PRIVATE signature_store_core_test.cpp signature_store_integration_test.cpp)
endif()

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
        GTest::gtest
        GTest::gtest_main
        sqlite3
        pthread
)
if(VHSM_LEDGER)
    target_link_libraries(vhsm_signature_store_test PRIVATE vhsm_ledger)
endif()

# Disable some warnings for test build
target_compile_options(vhsm_signature_store_test PRIVATE -O1 -g -Wno-self-move -Wno-format-truncation)

# Add test to enable testing
include(GoogleTest)
gtest_discover_tests(vhsm_signature_store_test)
