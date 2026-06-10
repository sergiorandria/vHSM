cmake_minimum_required(VERSION 3.21)
project(VirtualHSM LANGUAGES C CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
set(VHSM_DB_BACKEND "sqlite" CACHE STRING "Database backend: sqlite|postgres|mysql")
option(VHSM_ASYNC_DB         "Use async write queue for DB"             OFF)
option(VHSM_REQUIRE_DB       "Fail C_Sign if DB write fails"            ON)
option(VHSM_ADMIN_GRPC       "Build gRPC admin server"                  ON)
option(VHSM_NOTIFY_EMAIL     "Build email notification adapter"         ON)
option(VHSM_NOTIFY_WEBHOOK   "Build webhook notification adapter"       ON)
set(VHSM_NOTIFY_BUS_SIZE "1024" CACHE STRING "Notification ring buffer capacity")

# ---------------------------------------------------------------------------
# C++ standard
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Compiler hardening flags
# NOTE: -fPIE / -pie and -Wl,... are linker flags, not compile flags.
#       Pass them through the correct CMake variables.
# ---------------------------------------------------------------------------
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -O2
        -Wall
        -Wextra
        -Werror
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -fPIE
    )
    # Linker hardening flags — applied to all link steps
    add_link_options(
        -pie
        -Wl,-z,relro,-z,now
    )
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    add_compile_options(
        /W4 /WX /GS /GL /sdl
        /guard:cf /dynamicbase /nxcompat /highentropyva
    )
endif()

# ---------------------------------------------------------------------------
# Include directories
# ---------------------------------------------------------------------------
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# ---------------------------------------------------------------------------
# Find packages
#
# KEY FIX: find gRPC BEFORE Protobuf (or remove the standalone
# find_package(Protobuf) entirely).
#
# gRPC's gRPCConfig.cmake calls find_dependency(Protobuf) internally.
# If you call find_package(Protobuf) first, CMake defines the core protobuf
# targets (libprotobuf, libprotoc, ...).  When gRPC later calls
# find_dependency(Protobuf), it tries to define those same targets AGAIN
# plus the newer upb targets — CMake rejects the partial re-definition.
#
# Solution: let gRPC own the Protobuf find.  Its find_dependency call
# defines all protobuf targets (old + upb) in one shot.  You can still
# use protobuf:: targets afterwards because they are already defined.
# ---------------------------------------------------------------------------

find_package(OpenSSL REQUIRED)

# --- gRPC (brings in Protobuf transitively) ---------------------------------
if(VHSM_ADMIN_GRPC)
    # CONFIG mode is required for modern gRPC/protobuf installations.
    # This also defines all protobuf:: targets via find_dependency(Protobuf).
    find_package(gRPC CONFIG REQUIRED)

    # Convenience: expose the protoc / grpc_cpp_plugin executables for
    # .proto compilation later (works whether installed or via FetchContent).
    if(NOT TARGET gRPC::grpc_cpp_plugin)
        message(FATAL_ERROR "gRPC found but grpc_cpp_plugin target is missing")
    endif()
else()
    # When gRPC is disabled we still need Protobuf if you use .proto files
    # elsewhere.  Use CONFIG mode for consistency with the version on disk.
    find_package(Protobuf CONFIG QUIET)
    if(NOT Protobuf_FOUND)
        # Fallback to the legacy FindProtobuf module (older distros).
        find_package(Protobuf QUIET)
    endif()
endif()

# --- Database backends ------------------------------------------------------
find_package(SQLite3    QUIET)
find_package(PostgreSQL QUIET)
# MySQL has no standard CMake module; try a config file, then pkg-config.
find_package(MySQL      QUIET)

# --- Optional dependencies --------------------------------------------------
find_package(CURL           QUIET)
find_package(nlohmann_json 3.11.0 QUIET)
find_package(GTest          QUIET)

# ---------------------------------------------------------------------------
# Validate & resolve the DB backend
# ---------------------------------------------------------------------------
if(VHSM_DB_BACKEND STREQUAL "sqlite")
    if(NOT SQLite3_FOUND)
        message(FATAL_ERROR "SQLite3 not found but selected as DB backend")
    endif()
    set(DB_LIBRARIES    SQLite::SQLite3)          # modern imported target
    set(DB_INCLUDE_DIRS ${SQLite3_INCLUDE_DIRS})

elseif(VHSM_DB_BACKEND STREQUAL "postgres")
    if(NOT PostgreSQL_FOUND)
        message(FATAL_ERROR "PostgreSQL not found but selected as DB backend")
    endif()
    set(DB_LIBRARIES    PostgreSQL::PostgreSQL)   # modern imported target
    set(DB_INCLUDE_DIRS ${PostgreSQL_INCLUDE_DIRS})

elseif(VHSM_DB_BACKEND STREQUAL "mysql")
    if(NOT MySQL_FOUND)
        message(FATAL_ERROR "MySQL not found but selected as DB backend")
    endif()
    set(DB_LIBRARIES    ${MySQL_LIBRARIES})
    set(DB_INCLUDE_DIRS ${MySQL_INCLUDE_DIRS})

else()
    message(FATAL_ERROR "Unknown DB backend: ${VHSM_DB_BACKEND}")
endif()

# ---------------------------------------------------------------------------
# Validate optional adapters
# ---------------------------------------------------------------------------
if(VHSM_NOTIFY_EMAIL AND NOT CURL_FOUND)
    message(WARNING "CURL not found — disabling email notification adapter")
    set(VHSM_NOTIFY_EMAIL OFF CACHE BOOL "" FORCE)
endif()

if(VHSM_NOTIFY_WEBHOOK AND NOT CURL_FOUND)
    message(WARNING "CURL not found — disabling webhook notification adapter")
    set(VHSM_NOTIFY_WEBHOOK OFF CACHE BOOL "" FORCE)
endif()

# ---------------------------------------------------------------------------
# Compile definitions
#
# NOTE: Boolean options expand to ON/OFF strings, so the macro names become
#   VHSM_ASYNC_DB_ON  or  VHSM_ASYNC_DB_OFF  — which is unusual.
# It is more idiomatic to emit plain 0/1 defines or presence-only defines.
# Using generator expressions keeps this correct regardless of cache edits.
# ---------------------------------------------------------------------------
add_compile_definitions(
    VHSM_DB_BACKEND_${VHSM_DB_BACKEND}          # e.g. VHSM_DB_BACKEND_sqlite
    $<$<BOOL:${VHSM_ASYNC_DB}>:VHSM_ASYNC_DB>
    $<$<BOOL:${VHSM_REQUIRE_DB}>:VHSM_REQUIRE_DB>
    $<$<BOOL:${VHSM_ADMIN_GRPC}>:VHSM_ADMIN_GRPC>
    $<$<BOOL:${VHSM_NOTIFY_EMAIL}>:VHSM_NOTIFY_EMAIL>
    $<$<BOOL:${VHSM_NOTIFY_WEBHOOK}>:VHSM_NOTIFY_WEBHOOK>
    VHSM_NOTIFY_BUS_SIZE=${VHSM_NOTIFY_BUS_SIZE}
)

# ---------------------------------------------------------------------------
# Subdirectories
# ---------------------------------------------------------------------------
add_subdirectory(src)
add_subdirectory(tests)
# add_subdirectory(tools)

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
install(DIRECTORY include/ DESTINATION include)