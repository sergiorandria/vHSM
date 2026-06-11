# Keystore Unit Tests
<<<<<<< HEAD
<<<<<<< HEAD

find_package(GTest REQUIRED)

add_executable(vhsm_keystore_test
    attribute_store_test.cpp
    hsm_object_test.cpp
    key_wrap_test.cpp
    object_store_test.cpp
)

# Include the project root so tests can include headers as <keystore/...>
target_include_directories(vhsm_keystore_test PRIVATE ${PROJECT_SOURCE_DIR})

target_link_libraries(vhsm_keystore_test
    PRIVATE
    vhsm_keystore
    GTest::gtest_main
)

add_test(NAME vhsm_keystore_test COMMAND vhsm_keystore_test)
=======
=======
>>>>>>> 886025d0ccfc8b68813a05f5d5d8926b5c61713b
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

<<<<<<< HEAD
add_test(NAME vhsm_fingerprint_test COMMAND vhsm_fingerprint_test)
>>>>>>> 886025d (Build Files)
=======
add_test(NAME vhsm_fingerprint_test COMMAND vhsm_fingerprint_test)
>>>>>>> 886025d0ccfc8b68813a05f5d5d8926b5c61713b
