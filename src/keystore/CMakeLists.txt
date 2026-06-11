add_library(vhsm_keystore)

target_sources(vhsm_keystore
    PRIVATE
    hsm_object.cpp
    attribute_store.cpp
    object_store.cpp
    key_wrap.cpp
    key_fingerprint.cpp
)

target_include_directories(vhsm_keystore
    PUBLIC ${PROJECT_SOURCE_DIR}
)

find_package(OpenSSL REQUIRED)

target_link_libraries(vhsm_keystore
    PUBLIC
    vhsm_core
    vhsm_crypto
    OpenSSL::SSL
)