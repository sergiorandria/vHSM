cmake_minimum_required(VERSION 3.21)
project(VirtualHSM LANGUAGES C CXX)

# Options as per plan
option(VHSM_DB_BACKEND "Database backend: sqlite|postgres|mysql" "sqlite")
option(VHSM_ASYNC_DB "Use async write queue for DB" OFF)
option(VHSM_REQUIRE_DB "Fail C_Sign if DB write fails" ON)
option(VHSM_ADMIN_GRPC "Build gRPC admin server" ON)
option(VHSM_NOTIFY_EMAIL "Build email notification adapter" ON)
option(VHSM_NOTIFY_WEBHOOK "Build webhook notification adapter" ON)
option(VHSM_NOTIFY_BUS_SIZE "Notification ring buffer capacity" 1024)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler hardening flags (if GCC/Clang/MSVC)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall
        -Wextra
        -Werror
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -fPIE
        -pie
        -Wl,-z,relro,-z,now
    )
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    add_compile_options(
        /W4
        /WX
        /GS
        /GL
        /sdl
        /guard:cf
        /dynamicbase
        /nxcompat
        /highentropyva
    )
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Find packages
find_package(OpenSSL REQUIRED)
# SQLite3
find_package(SQLite3 QUIET)
# PostgreSQL
find_package(PostgreSQL QUIET)
# MySQL
find_package(MySQL QUIET)
# libcurl
find_package(CURL QUIET)
# protobuf
find_package(Protobuf REQUIRED)
# gRPC
find_package(gRPC REQUIRED)
# spdlog (maybe via find_package or fallback to submodule)
# nlohmann_json
find_package(nlohmann_json 3.11.0 QUIET)
# Google Test (for tests)
find_package(GTest QUIET)

# Set DB backend specific libraries
if(VHSM_DB_BACKEND STREQUAL "sqlite")
    if(SQLite3_FOUND)
        set(DB_LIBRARIES ${SQLite3_LIBRARIES})
        set(DB_INCLUDE_DIRS ${SQLite3_INCLUDE_DIRS})
    else()
        message(FATAL_ERROR "SQLite3 not found but selected as DB backend")
    endif()
elseif(VHSM_DB_BACKEND STREQUAL "postgres")
    if(PostgreSQL_FOUND)
        set(DB_LIBRARIES ${PostgreSQL_LIBRARIES})
        set(DB_INCLUDE_DIRS ${PostgreSQL_INCLUDE_DIRS})
    else()
        message(FATAL_ERROR "PostgreSQL not found but selected as DB backend")
    endif()
elseif(VHSM_DB_BACKEND STREQUAL "mysql")
    if(MySQL_FOUND)
        set(DB_LIBRARIES ${MySQL_LIBRARIES})
        set(DB_INCLUDE_DIRS ${MySQL_INCLUDE_DIRS})
    else()
        message(FATAL_ERROR "MySQL not found but selected as DB backend")
    endif()
else()
    message(FATAL_ERROR "Unknown DB backend: ${VHSM_DB_BACKEND}")
endif()

# Notification adapters
set(NOTIFICATION_ADAPTERS)
if(VHSM_NOTIFY_EMAIL)
    if(CURL_FOUND)
        list(APPEND NOTIFICATION_ADAPTERS email)
    else()
        message(WARNING "CURL not found, disabling email notification adapter")
        set(VHSM_NOTIFY_EMAIL OFF)
    endif()
endif()
if(VHSM_NOTIFY_WEBHOOK)
    if(CURL_FOUND)
        list(APPEND NOTIFICATION_ADAPTERS webhook)
    else()
        message(WARNING "CURL not found, disabling webhook notification adapter")
        set(VHSM_NOTIFY_WEBHOOK OFF)
    endif()
endif()

# gRPC adapter always requires gRPC and protobuf
if(VHSM_ADMIN_GRPC)
    if(NOT gRPC_FOUND)
        message(FATAL_ERROR "gRPC not found but admin gRPC enabled")
    endif()
endif()

# Define compile definitions
add_compile_definitions(
    VHSM_DB_BACKEND_${VHSM_DB_BACKEND}
    VHSM_ASYNC_DB_${VHSM_ASYNC_DB}
    VHSM_REQUIRE_DB_${VHSM_REQUIRE_DB}
    VHSM_ADMIN_GRPC_${VHSM_ADMIN_GRPC}
    VHSM_NOTIFY_EMAIL_${VHSM_NOTIFY_EMAIL}
    VHSM_NOTIFY_WEBHOOK_${VHSM_NOTIFY_WEBHOOK}
    VHSM_NOTIFY_BUS_SIZE=${VHSM_NOTIFY_BUS_SIZE}
)

# Subdirectories
add_subdirectory(src)
# add_subdirectory(tests)  # maybe later
# add_subdirectory(tools)  # maybe later

# Install (optional)
install(DIRECTORY include/ DESTINATION include)