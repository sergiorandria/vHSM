add_library(vhsm_crypto)

# Production primitives only. The toy FHE research code lives in the
# separate vhsm_crypto_fhe_experimental target below so a future
# `#include "fhe_scheme.h"` cannot silently pull it into a production
# dependency graph (fhe_scheme.h is documented NOT-secure, toy parameters).
target_sources(vhsm_crypto
    PRIVATE
    rsa.cpp
    ecc.cpp
    crypto_engine.cpp
    aes_gcm.cpp
    ctr_drbg_aes256.cpp
    secure_rng.cpp
    aes_ecb.cpp
)

target_include_directories(vhsm_crypto
    PUBLIC ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(vhsm_crypto
    PUBLIC vhsm_crypto_provider
)
if(WIN32)
    target_link_libraries(vhsm_crypto PRIVATE bcrypt)
endif()
