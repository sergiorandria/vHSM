add_library(vhsm_keystore)

target_sources(vhsm_keystore
    PRIVATE
    hsm_object.cpp
    attribute_store.cpp
    object_store.cpp
    internal/token_core.cpp
    key_wrap.cpp
    key_fingerprint.cpp
    key_rotation.cpp
    token.cpp 
    slot.cpp
)

target_include_directories(vhsm_keystore
    PUBLIC ${PROJECT_SOURCE_DIR}/src
)

target_link_libraries(vhsm_keystore
    PUBLIC
    vhsm_core
    vhsm_crypto
    vhsm_crypto_provider
)