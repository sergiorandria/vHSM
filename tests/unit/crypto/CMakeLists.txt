# Crypto Unit Tests

find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)

add_executable(vhsm_crypto_test
    rsa_test.cpp
    aes_gcm_test.cpp
    ecc_test.cpp
)

# Include the project root so tests can include headers as <crypto/...>
target_include_directories(vhsm_crypto_test PRIVATE ${PROJECT_SOURCE_DIR})

target_link_libraries(vhsm_crypto_test
    PRIVATE
    vhsm_crypto
    OpenSSL::Crypto
    GTest::gtest_main
)

add_test(NAME vhsm_crypto_test COMMAND vhsm_crypto_test)