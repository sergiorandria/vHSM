# Keystore Unit Tests

find_package(GTest QUIET)

add_executable(vhsm_keystore_test
    attribute_store_test.cpp
    hsm_object_test.cpp
    key_wrap_test.cpp
    object_store_test.cpp
    key_fingerprint_test.cpp
    token_core_test.cpp
    key_rotation_test.cpp
)

# Include the project root so tests can include headers as <keystore/...>
target_include_directories(vhsm_keystore_test PRIVATE ${PROJECT_SOURCE_DIR})

target_link_libraries(vhsm_keystore_test
    PRIVATE
    vhsm_keystore
    GTest::gtest_main
)

add_test(NAME vhsm_keystore_test COMMAND vhsm_keystore_test)

# Slot/Token/SlotManager unit tests (covers vhsm_keystore + vhsm_session).
add_executable(vhsm_slot_token_test
    slot_token_slot_manager.cpp
)

target_include_directories(vhsm_slot_token_test PRIVATE ${PROJECT_SOURCE_DIR})

target_link_libraries(vhsm_slot_token_test
    PRIVATE
    vhsm_keystore
    vhsm_session
    GTest::gtest_main
)

add_test(NAME vhsm_slot_token_test COMMAND vhsm_slot_token_test)

# Placeholder - add test files as they are created

if(NOT VHSM_USE_SECURE_CRYPTO)
  find_package(OpenSSL REQUIRED)
endif()
find_package(GTest QUIET)

add_executable(vhsm_fingerprint_test
    key_fingerprint_test.cpp
    ../../../src/keystore/key_fingerprint.cpp
)

# Include the project root so tests can include headers as <keystore/...>
target_include_directories(vhsm_fingerprint_test PRIVATE ${PROJECT_SOURCE_DIR})

target_link_libraries(vhsm_fingerprint_test
    PRIVATE
    vhsm_crypto
    vhsm_crypto_provider
    GTest::gtest_main
)

# This TU uses the shim's EC/RSA keygen (via vhsm::crypto wrappers), so the
# shim typedefs must stay enabled — consistent with the rest of the build.
target_compile_definitions(vhsm_fingerprint_test PRIVATE VHSM_OPENSSL_SHIM=1)

add_test(NAME vhsm_fingerprint_test COMMAND vhsm_fingerprint_test)
