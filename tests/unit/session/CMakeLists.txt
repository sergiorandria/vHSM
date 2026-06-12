# Session Unit Tests
find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)

add_executable(vhsm_session_test
    session_manager_test.cpp
    session_test.cpp
)

# Include the project root so tests can include headers as <crypto/...>
target_include_directories(vhsm_session_test PRIVATE ${PROJECT_SOURCE_DIR})

target_link_libraries(vhsm_session_test
    PRIVATE
    vhsm_session
    OpenSSL::Crypto
    GTest::gtest_main
)

add_test(NAME vhsm_session_test COMMAND vhsm_session_test)