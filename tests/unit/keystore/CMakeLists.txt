# Keystore Unit Tests

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