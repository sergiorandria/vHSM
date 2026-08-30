add_library(vhsm_metrics)

target_sources(vhsm_metrics
    PRIVATE
    metrics.cpp
)

target_include_directories(vhsm_metrics
    PUBLIC ${PROJECT_SOURCE_DIR}/src
)
