# vHSM persistence — encrypted vault (PLAN.md Phase 7).
#
# Vault: AES-256-GCM on-disk envelope keyed by a PBKDF2-derived key; atomic
# writes (temp + rename); migration registry for forward format upgrades.
# TokenSerializer: versioned binary encoding of token state for Backup/Restore.

add_library(vhsm_persistence)

target_sources(vhsm_persistence
    PRIVATE
    vault.cpp
    vault.h
    vault_format.h
    kdf.cpp
    kdf.h
    token_serializer.cpp
    token_serializer.h
    migrations.cpp
    migrations.h
)

target_include_directories(vhsm_persistence
    PUBLIC ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(vhsm_persistence
    PUBLIC
    vhsm_core
    vhsm_crypto
    vhsm_keystore
    vhsm_crypto_provider
)