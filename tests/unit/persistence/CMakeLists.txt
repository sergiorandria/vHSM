# Persistence Unit Tests (vault + serializer + migrations, PLAN.md Phase 7)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/unit/persistence)

add_executable(vhsm_persistence_test
    vault_unit_tests.cpp
    serializer_unit_tests.cpp
    migration_tests.cpp
    vault_serializer_integration_test.cpp
    kdf_unit_tests.cpp
)

target_include_directories(vhsm_persistence_test
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../src
)

target_link_libraries(vhsm_persistence_test
    PRIVATE
        vhsm_persistence
        vhsm_core
        vhsm_crypto
        vhsm_keystore
        GTest::gtest
        GTest::gtest_main
)

# Disable warnings that are triggered by the tests but are not issues in the test context
target_compile_options(vhsm_persistence_test PRIVATE -O1 -g -Wno-self-move)

include(GoogleTest)
gtest_discover_tests(vhsm_persistence_test)