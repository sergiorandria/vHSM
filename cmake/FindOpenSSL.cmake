# - Find OpenSSL
# This module defines the following variables:
#  OpenSSL_FOUND - system has OpenSSL
#  OpenSSL_INCLUDE_DIRS - include directories
#  OpenSSL_LIBRARIES - link these to use OpenSSL
#  OpenSSL::SSL and OpenSSL::Crypto targets (if using CMake targets)

find_package(OpenSSL QUIET)
if(OPENSSL_FOUND)
    set(OpenSSL_FOUND TRUE)
    set(OpenSSL_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})
    set(OpenSSL_LIBRARIES ${OPENSSL_LIBRARIES})
    # Provide imported targets if not already provided by FindOpenSSL
    if(NOT TARGET OpenSSL::SSL)
        add_library(OpenSSL::SSL UNKNOWN IMPORTED)
        set_target_properties(OpenSSL::SSL PROPERTIES
            IMPORTED_LOCATION ${OPENSSL_LIBRARIES}
            INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR}
        )
    endif()
    if(NOT TARGET OpenSSL::Crypto)
        add_library(OpenSSL::Crypto UNKNOWN IMPORTED)
        set_target_properties(OpenSSL::Crypto PROPERTIES
            IMPORTED_LOCATION ${OPENSSL_LIBRARIES}
            INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR}
        )
    endif()
else()
    set(OpenSSL_FOUND FALSE)
endif()
mark_as_advanced(OpenSSL_INCLUDE_DIRS OpenSSL_LIBRARIES)