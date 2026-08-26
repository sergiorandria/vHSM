# TSan stress suite — built only when VHSM_ENABLE_TSAN=ON.
add_executable(stress_tsan
    tsan/stress_tsan.cpp
    ${PROJECT_SOURCE_DIR}/src/audit/audit_log.cpp
)

target_include_directories(stress_tsan
    PRIVATE ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(stress_tsan
    PRIVATE
        vhsm_session
        vhsm_secure_crypto
        GTest::gtest
        GTest::gtest_main
)

target_compile_options(stress_tsan PRIVATE -Wno-self-move)

gtest_discover_tests(stress_tsan)
