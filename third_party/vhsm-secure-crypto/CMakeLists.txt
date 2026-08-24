cmake_minimum_required(VERSION 3.21)
project(vhsm_secure_crypto VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Hardening flags — same as top-level
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIC)
    add_link_options(-Wl,-z,relro,-z,now)
endif()

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(VHSM_SCRYPTO_ENABLE_TESTS "Build self-tests" ON)
option(VHSM_SCRYPTO_PURE "No OpenSSL fallback for RSA/EC math (requires bignum impl)" OFF)

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
add_library(vhsm_secure_crypto STATIC)

target_include_directories(vhsm_secure_crypto
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_sources(vhsm_secure_crypto PRIVATE
    src/mem/secure_cleanse.cpp
    src/mem/secure_mlock.cpp
    src/hash/sha256.cpp
    src/hash/sha512.cpp
    src/hmac/hmac_sha256.cpp
    src/kdf/pbkdf2.cpp
    src/kdf/hkdf.cpp
    src/cipher/aes_core.cpp
    src/cipher/aes_gcm.cpp
    src/cipher/aes_ecb.cpp
    src/rng/secure_rng.cpp
    src/rng/ctr_drbg.cpp
    src/pkey/rsa_policy.cpp
    src/pkey/ec_policy.cpp
    src/compat/evp_compat.cpp
    src/selftest.cpp
)

if(WIN32)
    target_link_libraries(vhsm_secure_crypto PUBLIC bcrypt)
endif()

# If not pure, we still link OpenSSL for big-integer RSA/EC math but only via
# isolated detail namespace — API is still vhsm::scrypto::*
if(NOT VHSM_SCRYPTO_PURE)
    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND OR OPENSSL_FOUND)
        target_link_libraries(vhsm_secure_crypto PUBLIC OpenSSL::Crypto)
        target_compile_definitions(vhsm_secure_crypto PUBLIC VHSM_SCRYPTO_HAS_OPENSSL=1)
    else()
        message(WARNING "vhsm_secure_crypto: OpenSSL not found — RSA/EC will be stub (hash/AES still work)")
        target_compile_definitions(vhsm_secure_crypto PUBLIC VHSM_SCRYPTO_HAS_OPENSSL=0)
    endif()
else()
    target_compile_definitions(vhsm_secure_crypto PUBLIC VHSM_SCRYPTO_HAS_OPENSSL=0)
endif()

# Self-test executable
if(VHSM_SCRYPTO_ENABLE_TESTS)
    add_executable(vhsm_scrypto_selftest tests/selftest_main.cpp)
    target_link_libraries(vhsm_scrypto_selftest PRIVATE vhsm_secure_crypto)
    add_test(NAME vhsm_scrypto_selftest COMMAND vhsm_scrypto_selftest)
endif()

# Install
include(GNUInstallDirs)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS vhsm_secure_crypto EXPORT vhsm_secure_cryptoTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
