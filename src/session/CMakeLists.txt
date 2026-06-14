add_library(vhsm_session)

target_sources(vhsm_session
    PRIVATE
    session_manager.cpp
    session.cpp
    FindContext.cpp
    SignContext.cpp
    slot_manager.cpp
)

target_include_directories(vhsm_session
    PUBLIC ${PROJECT_SOURCE_DIR}
)

target_link_libraries(vhsm_session
    PUBLIC
    vhsm_core
    vhsm_crypto
    vhsm_keystore
    OpenSSL::SSL
)
