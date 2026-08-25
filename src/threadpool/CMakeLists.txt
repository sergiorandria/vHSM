add_library(vhsm_threadpool
    thread_pool.cpp
)

target_include_directories(vhsm_threadpool
    PUBLIC ${PROJECT_SOURCE_DIR}/src
)

# thread_pool.h logs through vhsm::log::global_logger(), so every consumer
# needs the logger symbols — link PUBLICly.
target_link_libraries(vhsm_threadpool
    PUBLIC vhsm_log
)
