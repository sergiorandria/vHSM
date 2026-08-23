add_library(vhsm_threadpool
    thread_pool.cpp
)

target_include_directories(vhsm_threadpool
    PUBLIC ${PROJECT_SOURCE_DIR}/src
)