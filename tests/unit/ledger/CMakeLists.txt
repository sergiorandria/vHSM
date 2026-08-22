# Ledger Unit Tests — only when ledger integration is enabled
if(NOT VHSM_LEDGER)
    return()
endif()

add_executable(vhsm_ledger_test
    ledger_client_test.cpp
)

target_include_directories(vhsm_ledger_test
    PRIVATE
        ${PROJECT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/src/ledger
        ${PROJECT_SOURCE_DIR}/src/threadpool
)

target_link_libraries(vhsm_ledger_test
    PRIVATE
        vhsm_ledger
        vhsm_threadpool
        vhsm_notification
        vhsm_core
        fabric-gateway-cpp
        nlohmann_json::nlohmann_json
        GTest::gtest
        GTest::gtest_main
)

target_compile_options(vhsm_ledger_test PRIVATE -O1 -g)

include(GoogleTest)
gtest_discover_tests(vhsm_ledger_test)