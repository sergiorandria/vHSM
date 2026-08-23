add_executable(vhsm_abi_test abi_test.cpp)

target_include_directories(vhsm_abi_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../src
)

target_link_libraries(vhsm_abi_test PRIVATE
    vhsm_core
    GTest::gtest
    GTest::gtest_main
)

target_compile_options(vhsm_abi_test PRIVATE -O3 -flto -fvisibility=hidden -fvisibility-inlines-hidden)

include(GoogleTest)
gtest_discover_tests(vhsm_abi_test)
