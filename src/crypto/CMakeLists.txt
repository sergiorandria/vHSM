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
    fips.cpp
    pqc_provider.cpp
)

target_include_directories(vhsm_crypto
    PUBLIC ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(vhsm_crypto
    PUBLIC vhsm_crypto_provider
    PUBLIC vhsm_metrics
)

# Post-quantum signatures (Dilithium/SPHINCS+) via liboqs. Opt-in: off by
# default so the production build never depends on liboqs. When enabled, the
# PqcProvider compiles its real OQS-backed implementation and links liboqs.
option(VHSM_PQC "Enable post-quantum (Dilithium/SPHINCS+) hybrid signatures via liboqs" OFF)
if(VHSM_PQC)
  find_package(OQS CONFIG REQUIRED)
  if(NOT TARGET OQS::oqs)
    find_library(OQS_LIB NAMES oqs REQUIRED)
    add_library(OQS::oqs UNKNOWN IMPORTED)
    set_target_properties(OQS::oqs PROPERTIES IMPORTED_LOCATION ${OQS_LIB})
  endif()
  target_compile_definitions(vhsm_crypto PUBLIC VHSM_PQC)
  target_link_libraries(vhsm_crypto PUBLIC OQS::oqs)
endif()
if(WIN32)
    target_link_libraries(vhsm_crypto PRIVATE bcrypt)
endif()
