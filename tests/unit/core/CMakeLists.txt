# Core Unit Tests
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/unit/core)

add_executable(vhsm_core_test
    secure_buffer_test.cpp
    clock_test.cpp
    thread_pool_test.cpp
)

target_include_directories(vhsm_core_test
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/core
)

target_link_libraries(vhsm_core_test
    PRIVATE
        vhsm_core
        vhsm_threadpool
        GTest::gtest
        GTest::gtest_main
)

# Disable warnings that are triggered by the tests but are not issues in the test context
target_compile_options(vhsm_core_test PRIVATE -O1 -g -Wno-self-move -Wno-format-truncation)

# HSM Instance Tests (with database and schema integration)
add_executable(vhsm_hsm_instance_test
    hsm_instance_test.cpp
)

target_include_directories(vhsm_hsm_instance_test
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/core
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/signature_store
)

target_link_libraries(vhsm_hsm_instance_test
    PRIVATE
        vhsm_core
        vhsm_signature_store
        GTest::gtest
        GTest::gtest_main
        SQLite3::SQLite3
)

target_compile_options(vhsm_hsm_instance_test PRIVATE -O1 -g -Wno-error=attributes -Wno-attributes)

# Add tests to enable testing
include(GoogleTest)
gtest_discover_tests(vhsm_core_test)
gtest_discover_tests(vhsm_hsm_instance_test)