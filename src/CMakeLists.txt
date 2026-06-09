# Virtual HSM core library
add_library(vhsm SHARED
    # core
    core/types.h
    core/error.h core/error.cpp
    core/utils.h core/utils.cpp
    core/secure_buffer.h
    core/clock.h
    # crypto
    crypto/crypto_engine.h crypto/crypto_engine.cpp
    crypto/aes_gcm.h crypto/aes_gcm.cpp
    crypto/rsa.h crypto/rsa.cpp
    crypto/ecc.h crypto/ecc.cpp
    crypto/hmac.h crypto/hmac.cpp
    crypto/kdf.h crypto/kdf.cpp
    crypto/digest.h crypto/digest.cpp
    crypto/rng.h crypto/rng.cpp
    crypto/mechanisms.h
    # keystore
    keystore/hsm_object.h
    keystore/token.h keystore/token.cpp
    keystore/slot.h keystore/slot.cpp
    keystore/object_store.h keystore/object_store.cpp
    keystore/attribute_store.h
    keystore/key_wrap.h keystore/key_wrap.cpp
    keystore/key_fingerprint.h keystore/key_fingerprint.cpp
    # session
    session/session.h session/session.cpp
    session/session_manager.h session/session_manager.cpp
    session/slot_manager.h session/slot_manager.cpp
    session/access_control.h
    session/find_context.h
    session/op_context.h
    # signature_store
    signature_store/db_config.h
    signature_store/db_connection.h signature_store/db_connection.cpp
    signature_store/db_schema.h signature_store/db_schema.cpp
    signature_store/db_hmac_key.h signature_store/db_hmac_key.cpp
    signature_store/row_integrity.h signature_store/row_integrity.cpp
    signature_store/signature_repository.h signature_store/signature_repository.cpp
    signature_store/signature_dispatcher.h signature_store/signature_dispatcher.cpp
    signature_store/signature_query.h signature_store/signature_query.cpp
    signature_store/verification_service.h signature_store/verification_service.cpp
    signature_store/notification_repository.h signature_store/notification_repository.cpp
    # notification
    notification/notification_event.h
    notification/notification_bus.h notification/notification_bus.cpp
    notification/notification_dispatcher.h notification/notification_dispatcher.cpp
    notification/adapters/email_adapter.h notification/adapters/email_adapter.cpp
    notification/adapters/webhook_adapter.h notification/adapters/webhook_adapter.cpp
    notification/adapters/grpc_push_adapter.h notification/adapters/grpc_push_adapter.cpp
    # pkcs11
    pkcs11/pkcs11.h
    pkcs11/p11_init.cpp
    pkcs11/p11_slot.cpp
    pkcs11/p11_session.cpp
    pkcs11/p11_object.cpp
    pkcs11/p11_crypto.cpp
    pkcs11/p11_keygen.cpp
    pkcs11/p11_wrap.cpp
    pkcs11/p11_random.cpp
    pkcs11/function_list.cpp
    # persistence
    persistence/vault.h persistence/vault.cpp
    persistence/vault_format.h
    persistence/token_serializer.h persistence/token_serializer.cpp
    persistence/migrations.h persistence/migrations.cpp
    # admin
    admin/admin_server.h admin/admin_server.cpp
    admin/audit_log.h admin/audit_log.cpp
)

# Include directories for this library
target_include_directories(vhsm PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<INSTALL_INTERFACE:include>
)

# Link libraries
target_link_libraries(vhsm
    PRIVATE
        OpenSSL::SSL OpenSSL::Crypto
        ${DB_LIBRARIES}
        ${CURL_LIBRARIES}
        Protobuf::libprotobuf
        gRPC::grpc++
        gRPC::grpcpp
        gRPC::grpcpp_unsecure
    # If using nlohmann_json
    )
if(TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(vhsm PRIVATE nlohmann_json::nlohmann_json)
endif()
if(TARGET GTest::GTest)
    # For tests, not linking here
endif()

# Set properties
set_target_properties(vhsm PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)

# Define exported targets
install(TARGETS vhsm
    EXPORT VirtualHSMTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

# Static library variant
add_library(vhsm_static STATIC
    ${vhsm_SOURCES}
)
target_include_directories(vhsm_static PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(vhsm_static
    PRIVATE
        OpenSSL::SSL OpenSSL::Crypto
        ${DB_LIBRARIES}
        ${CURL_LIBRARIES}
        Protobuf::libprotobuf
        gRPC::grpc++
        gRPC::grpcpp
        gRPC::grpcpp_unsecure
)
if(TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(vhsm_static PRIVATE nlohmann_json::nlohmann_json)
endif()
set_target_properties(vhsm_static PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON
)

install(TARGETS vhsm_static
    EXPORT VirtualHSMTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

# Admin gRPC server (if enabled)
if(VHSM_ADMIN_GRPC)
    add_library(vhsm_admin_server SHARED
        admin/admin_server.h admin/admin_server.cpp
        admin/audit_log.h admin/audit_log.cpp
    )
    target_include_directories(vhsm_admin_server PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
        $<INTERFACE_INCLUDE_DIRECTORIES:vhsm>
    )
    target_link_libraries(vhsm_admin_server
        PRIVATE
            vhsm
            gRPC::grpc++
            gRPC::grpcpp
            Protobuf::libprotobuf
    )
    set_target_properties(vhsm_admin_server PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
    )
    install(TARGETS vhsm_admin_server
        EXPORT VirtualHSMTargets
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
    )
endif()

# Export package
install(EXPORT VirtualHSMTargets
    FILE VirtualHSMTargets.cmake
    NAMESPACE VirtualHSM::
    DESTINATION lib/cmake/VirtualHSM
)