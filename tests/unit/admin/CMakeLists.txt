# Admin Unit Tests

find_package(GTest QUIET)

add_executable(vhsm_admin_test
    admin_service_test.cpp
)

target_include_directories(vhsm_admin_test
    PRIVATE
        ${PROJECT_SOURCE_DIR}
)

target_link_libraries(vhsm_admin_test
    PRIVATE
        vhsm_admin
        vhsm_core
        vhsm_keystore
        vhsm_persistence
        vhsm_notification
        GTest::gtest_main
)

add_test(NAME vhsm_admin_test COMMAND vhsm_admin_test)