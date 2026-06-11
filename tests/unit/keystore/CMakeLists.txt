# Keystore Unit Tests
# Placeholder - add test files as they are created

find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)

add_executable(vhsm_fingerprint_test
    Key_fingerprint_test.cpp
    ../../../src/keystore/Key_fingerprint.cpp
)

# Include the project root so tests can include headers as <keystore/...>
target_include_directories(vhsm_fingerprint_test PRIVATE ${PROJECT_SOURCE_DIR})

target_link_libraries(vhsm_fingerprint_test
    PRIVATE
    vhsm_crypto
    OpenSSL::Crypto
    GTest::gtest_main
)

add_test(NAME vhsm_fingerprint_test COMMAND vhsm_fingerprint_test)