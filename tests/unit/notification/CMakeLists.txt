# Notification Unit Tests — skip if deps not found (CI without nlohmann_json/CURL/GTest)

find_package(nlohmann_json 3.11.0 QUIET)
find_package(CURL QUIET)
find_package(GTest QUIET)
if(NOT GTest_FOUND OR NOT nlohmann_json_FOUND)
  message(STATUS "GTest or nlohmann_json not found — skipping vhsm_notification_test")
  return()
endif()
if(NOT CURL_FOUND)
  message(STATUS "CURL not found — skipping vhsm_notification_test (needs adapters)")
  return()
endif()

add_executable(vhsm_notification_test
    bounded_bus_test.cpp
    adapter_test.cpp
)

target_include_directories(vhsm_notification_test
    PRIVATE
        ${PROJECT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/src/notification
)

target_link_libraries(vhsm_notification_test
    PRIVATE
        vhsm_notification
        vhsm_core
        CURL::libcurl
        nlohmann_json::nlohmann_json
        GTest::gtest
        GTest::gtest_main
)

target_compile_options(vhsm_notification_test PRIVATE -O1 -g)

include(GoogleTest)
gtest_discover_tests(vhsm_notification_test)