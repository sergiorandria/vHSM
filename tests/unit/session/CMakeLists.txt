# Session Unit Tests
# This CMakeLists builds the session unit test executable using GoogleTest.
# The test target links against the `vhsm_session` library and configures
# include directories so tests can include headers via "session/...".
#
# Output binary is placed under the per-directory 'build' folder used by the
# other unit test CMake files in this repository.

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/build)

add_executable(vhsm_session_test
    
    findcontext_test.cpp
    signcontext_test.cpp
)

target_include_directories(vhsm_session_test
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src/session
)

target_link_libraries(vhsm_session_test
    PRIVATE
        vhsm_session
        GTest::gtest
        GTest::gtest_main
)

# Disable some warnings for test build
target_compile_options(vhsm_session_test PRIVATE -O1 -g -Wno-self-move -Wno-format-truncation)

# Add test to enable testing
include(GoogleTest)
gtest_discover_tests(vhsm_session_test)
