# PKCS#11 Composition Root Tests

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/unit/pkcs11)

add_executable(vhsm_composition_root_test
    composition_root_test.cpp
)

target_include_directories(vhsm_composition_root_test
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src
)

target_link_libraries(vhsm_composition_root_test
    PRIVATE
        vhsm_pkcs11
        vhsm_signature_store
        vhsm_core
        vhsm_keystore
        vhsm_persistence
        vhsm_session
        vhsm_notification
        vhsm_threadpool
        vhsm_crypto_provider
        GTest::gtest
        GTest::gtest_main
        SQLite::SQLite3
)

target_compile_options(vhsm_composition_root_test PRIVATE -O1 -g)

include(GoogleTest)
gtest_discover_tests(vhsm_composition_root_test)
