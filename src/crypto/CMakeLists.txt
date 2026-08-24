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
    SecureRNG.cpp
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

# ─── Experimental: Gentry-style FHE on ideal lattices (TOY PARAMETERS) ────
# NOT secure — for research/demos only. Never link into production targets.
add_library(vhsm_crypto_fhe_experimental STATIC
    gentry_ideal_lattice.cpp
    gentry_polynomial.cpp
)
target_include_directories(vhsm_crypto_fhe_experimental
    PUBLIC ${PROJECT_SOURCE_DIR}/src
)
target_compile_definitions(vhsm_crypto_fhe_experimental
    PUBLIC VHSM_FHE_EXPERIMENTAL_TOY_NOT_SECURE)
