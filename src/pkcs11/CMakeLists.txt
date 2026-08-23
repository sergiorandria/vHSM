add_library(vhsm_pkcs11 OBJECT)

set(PKCS11_SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/p11_internal.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/p11_init.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/composition_root.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/p11_slot.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/p11_session.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/p11_object.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/p11_random.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/p11_crypto.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/p11_keygen.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/p11_wrap.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/function_list.cpp
)

target_sources(vhsm_pkcs11
    PRIVATE
    ${PKCS11_SRCS}
)

target_include_directories(vhsm_pkcs11
    PUBLIC ${PROJECT_SOURCE_DIR}
)

target_compile_options(vhsm_pkcs11 PRIVATE -fPIC -Wno-deprecated-declarations)

target_link_libraries(vhsm_pkcs11
    PUBLIC
    vhsm_core
    vhsm_crypto
    vhsm_keystore
    vhsm_persistence
    vhsm_session
    OpenSSL::SSL
)

# Shared module that can be loaded as a PKCS#11 .so
add_library(vhsm_pkcs11_mod SHARED $<TARGET_OBJECTS:vhsm_pkcs11>)
set_target_properties(vhsm_pkcs11_mod PROPERTIES
    OUTPUT_NAME "vhsm_pkcs11"
    POSITION_INDEPENDENT_CODE ON
)
target_compile_options(vhsm_pkcs11_mod PRIVATE -fPIC -Wno-deprecated-declarations)
target_link_libraries(vhsm_pkcs11_mod
    PUBLIC
    vhsm_core
    vhsm_crypto
    vhsm_keystore
    vhsm_persistence
    vhsm_session
    OpenSSL::SSL
)
