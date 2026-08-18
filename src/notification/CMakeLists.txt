add_library(vhsm_notification)

target_sources(vhsm_notification
    PRIVATE
    notification_bus.cpp
)

target_include_directories(vhsm_notification
    PUBLIC ${PROJECT_SOURCE_DIR}
)
