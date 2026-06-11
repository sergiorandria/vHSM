add_library(vhsm_crypto)

target_sources(vhsm_crypto
    PRIVATE
    rsa.cpp
    ecc.cpp
    aes_gcm.cpp
    ctr_drbg_aes256.cpp
    SecureRNG.cpp
    aes_ecb.cpp
)

target_include_directories(vhsm_crypto
    PUBLIC ${PROJECT_SOURCE_DIR}
)

find_package(OpenSSL REQUIRED)

target_link_libraries(vhsm_crypto
    PUBLIC OpenSSL::SSL
)