# ---------------------------------------------------------------------------
# pkcs11 — PKCS#11 shared library (the actual deliverable)
# Files: pkcs11.h, p11_init, p11_slot, p11_session, p11_object,
#        p11_crypto, p11_keygen, p11_wrap, p11_random, function_list
# ---------------------------------------------------------------------------
add_library(vhsm_pkcs11 SHARED
    # Uncomment as files are created:
    # p11_init.cpp
    # p11_slot.cpp
    # p11_session.cpp
    # p11_object.cpp
    # p11_crypto.cpp
    # p11_keygen.cpp
    # p11_wrap.cpp
    # p11_random.cpp
    # function_list.cpp
    ${CMAKE_SOURCE_DIR}/cmake/empty.cpp
)

# PKCS#11 tokens are loaded by name; strip the "lib" prefix on Linux so
# the token can be addressed as "vhsm_pkcs11" rather than "libvhsm_pkcs11".
set_target_properties(vhsm_pkcs11 PROPERTIES PREFIX "")

target_include_directories(vhsm_pkcs11
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(vhsm_pkcs11
    PRIVATE
        vhsm_core
        vhsm_crypto
        vhsm_keystore
        vhsm_session
        vhsm_persistence
        vhsm_signature_store
        vhsm_notification
        vhsm_admin
)

install(TARGETS vhsm_pkcs11
    LIBRARY  DESTINATION lib
    RUNTIME  DESTINATION bin
)