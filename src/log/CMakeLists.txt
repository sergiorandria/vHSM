add_library(vhsm_log STATIC
    logger.cpp
)

target_include_directories(vhsm_log PUBLIC ${PROJECT_SOURCE_DIR}/src)

# logger uses <sstream> macros and core macros
target_link_libraries(vhsm_log PUBLIC vhsm_core)
