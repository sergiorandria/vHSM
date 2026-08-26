# Throughput benchmark harness — built only when VHSM_ENABLE_BENCH=ON.
add_executable(vhsm_bench
    vhsm_bench.cpp
)

target_include_directories(vhsm_bench
    PRIVATE ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(vhsm_bench
    PRIVATE
        vhsm_pkcs11
        vhsm_signature_store
        SQLite3::SQLite3
)
