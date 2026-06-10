# Core Unit Tests
add_library(vhsm_core_test secure_buffer_test.cpp)

target_include_directories(vhsm_core_test
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/core
)

target_link_libraries(vhsm_core_test
    PRIVATE
        vhsm_core
        gtest_main
)

# Add test to enable testing
include(GoogleTest)
gtest_discover_tests(vhsm_core_test)