add_library(vhsm_notification)

target_sources(vhsm_notification
    PRIVATE
    notification_bus.cpp
    bounded_notification_bus.cpp
    email_adapter.cpp
    webhook_adapter.cpp
    grpc_push_adapter.cpp
)

target_include_directories(vhsm_notification
    PUBLIC ${PROJECT_SOURCE_DIR}
)

find_package(CURL REQUIRED)

target_link_libraries(vhsm_notification
    PUBLIC
    vhsm_core
    CURL::libcurl
)