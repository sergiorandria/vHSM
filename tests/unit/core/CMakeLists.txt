# Core Unit Tests
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/build)

add_executable(vhsm_core_test
    secure_buffer_test.cpp
    clock_test.cpp
)

target_include_directories(vhsm_core_test
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/core
)

target_link_libraries(vhsm_core_test
    PRIVATE
        vhsm_core
        GTest::gtest
        GTest::gtest_main
)

# Disable warnings that are triggered by the tests but are not issues in the test context
target_compile_options(vhsm_core_test PRIVATE -O1 -g -Wno-self-move -Wno-format-truncation)

# Add test to enable testing
include(GoogleTest)
gtest_discover_tests(vhsm_core_test)