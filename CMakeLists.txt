cmake_minimum_required(VERSION 3.21)
project(VirtualHSM VERSION 1.0.0 LANGUAGES C CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---------------------------------------------------------------------------
# Build performance
#
# - Default build type: an empty CMAKE_BUILD_TYPE silently drops ALL
#   optimization flags, so fall back to RelWithDebInfo (-O2 -g).
# - ccache: enabled automatically when installed on the host.
# ---------------------------------------------------------------------------
get_property(_vhsm_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT CMAKE_BUILD_TYPE AND NOT _vhsm_multi_config)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

find_program(VHSM_CCACHE_PROGRAM ccache)
if(VHSM_CCACHE_PROGRAM)
    set(CMAKE_C_COMPILER_LAUNCHER   "${VHSM_CCACHE_PROGRAM}")
    set(CMAKE_CXX_COMPILER_LAUNCHER "${VHSM_CCACHE_PROGRAM}")
    message(STATUS "VHSM: compiler cache enabled (${VHSM_CCACHE_PROGRAM})")
endif()

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
set(VHSM_STORE_BACKEND "db" CACHE STRING "Signature store backend: db|ledger")
set_property(CACHE VHSM_STORE_BACKEND PROPERTY STRINGS db ledger)
option(VHSM_USE_SECURE_CRYPTO "Use hardened vhsm-secure-crypto (third_party/vhsm-secure-crypto) instead of system OpenSSL" ON)

# Mutually exclusive backends: ledger is alternative to DB, not complementary.
# When STORE_BACKEND=ledger, force VHSM_LEDGER ON so Fabric code is built.
if(VHSM_STORE_BACKEND STREQUAL "ledger")
  set(VHSM_LEDGER ON CACHE BOOL "" FORCE)
endif()

# ---------------------------------------------------------------------------
# Version header generation
# ---------------------------------------------------------------------------
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/vhsm/version.h
    @ONLY
)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/generated)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

# Peak: include ABI hardening flags for every target via the helper.
include(cmake/CompilerFlags.cmake)

# ---------------------------------------------------------------------------
# C++ standard
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Compiler hardening flags
# NOTE: -fPIE / -pie and -Wl,... are linker flags, not compile flags.
#       Pass them through the correct CMake variables.
# NOTE: Optimization level (-O*) is intentionally NOT set here — it is owned
#       by CMAKE_BUILD_TYPE so Debug builds stay debuggable and Release/LTO
#       settings apply consistently.
# ---------------------------------------------------------------------------
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall
        -Wextra
        -Werror
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -fPIC
    )
    # Linker hardening flags — applied to all link steps
    # PIE is set per-executable only, to avoid -pie conflicting with -shared
    # when building shared libraries / loadable modules.
    add_link_options(
        -Wl,-z,relro,-z,now
    )
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")
    add_compile_definitions(_VHSMXX_HAVE_ATTRIBUTE_VISIBILITY)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # NOTE: /dynamicbase /nxcompat /highentropyva are LINKER options —
    # passing them to cl.exe only produces D9002 "ignoring unknown option".
    add_compile_options(
        /W4 /WX /GS /GL /sdl
        /guard:cf
    )
    add_link_options(/dynamicbase /nxcompat /highentropyva)
endif()

# ---------------------------------------------------------------------------
# Interprocedural optimization (LTO)
#
# Applied through CMake's IPO support (per-config properties) instead of
# hand-rolled -flto flags so that every target — including the shared
# PKCS#11 module — links with matching LTO objects automatically.
# ---------------------------------------------------------------------------
include(CheckIPOSupported)
check_ipo_supported(RESULT _vhsm_ipo_ok OUTPUT _vhsm_ipo_reason)
option(VHSM_ENABLE_IPO "Enable interprocedural optimization / LTO" ${_vhsm_ipo_ok})
if(VHSM_ENABLE_IPO)
    if(NOT _vhsm_ipo_ok)
        message(WARNING "VHSM_ENABLE_IPO=ON but LTO is not supported by this toolchain: ${_vhsm_ipo_reason}")
    else()
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE          TRUE)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO   TRUE)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL       TRUE)
        # Debug keeps -O0 so sanitizers/debuggers behave predictably.
    endif()
endif()

# Unity build: concatenates sources per target to cut full-build times.
# OFF by default because merged TUs can collide on file-local symbols.
# GCC additionally warns (-Werror=subobject-linkage) when gtest fixtures in
# anonymous namespaces are merged — suppressed only in unity mode.
# ThreadSanitizer stress suite: -DVHSM_ENABLE_TSAN=ON builds the stress
# target with TSan instrumentation. Requires debug info; IPO must stay off.
option(VHSM_ENABLE_TSAN "Build TSan stress suite (tests/stress/tsan)" OFF)
if(VHSM_ENABLE_TSAN)
    # -O2 (not -O0/-O1): _FORTIFY_SOURCE requires optimization, and TSan
    # needs frames intact — -O2 -g satisfies both. Fortify is harmless here.
    add_compile_options(-fsanitize=thread -g -O2)
    add_compile_options(-Wno-cpp)   # tolerate glibc fortify warnings from system headers
    add_link_options(-fsanitize=thread)
endif()

option(VHSM_UNITY_BUILD "Unity build (faster clean builds, slower incremental)" OFF)
set(CMAKE_UNITY_BUILD ${VHSM_UNITY_BUILD})
if(VHSM_UNITY_BUILD AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wno-subobject-linkage)
endif()

# Optional linker override ("default" keeps the toolchain driver choice).
# NOTE: lld is known-broken with GCC 16 LTO IR in some distros; keep "default"
# unless you have verified your combination.
set(VHSM_LINKER "default" CACHE STRING "Linker to use: default|bfd|lld|mold")
set_property(CACHE VHSM_LINKER PROPERTY STRINGS default bfd lld mold)
if(NOT VHSM_LINKER STREQUAL "default")
    include(CheckLinkerFlag)
    check_linker_flag(CXX "-fuse-ld=${VHSM_LINKER}" _vhsm_have_ld_${VHSM_LINKER})
    if(_vhsm_have_ld_${VHSM_LINKER})
        add_link_options(-fuse-ld=${VHSM_LINKER})
        message(STATUS "VHSM: using ${VHSM_LINKER} linker")
    else()
        message(WARNING "VHSM_LINKER=${VHSM_LINKER} not supported by this toolchain — keeping default")
    endif()
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

# Secure crypto clone (third_party/vhsm-secure-crypto) — hardened minimal OpenSSL replacement.
# Wired to the build unconditionally when VHSM_USE_SECURE_CRYPTO=ON.
# We use a provider interface so IDEs and clangd see the secure headers
# without breaking the legacy OpenSSL targets needed for RSA/EC math fallback
# (VHSM_SCRYPTO_PURE=OFF) and for fabric-gateway-cpp.
if(VHSM_USE_SECURE_CRYPTO)
    add_subdirectory(third_party/vhsm-secure-crypto)
    # The vendored library hardcodes -O2 via directory scope, which would
    # override the config-owned optimization level (e.g. downgrade -O3 in
    # Release). Re-append the correct level as a target option — target
    # options come after directory options, so they win.
    target_compile_options(vhsm_secure_crypto PRIVATE
        $<$<CONFIG:Debug>:-O0>
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:RelWithDebInfo>:-O2>
    )
    if(MSVC)
        # Vendored code has benign narrowing conversions (C4244/C4267) that
        # MSVC promotes to errors via the superproject's global /W4 /WX.
        # GCC/Clang never flagged them (no -Wconversion globally). Relax
        # W-error + the two warnings for THIS target only — first-party code
        # stays strict.
        target_compile_options(vhsm_secure_crypto PRIVATE
            /WX- /wd4244 /wd4267
        )
    endif()
    add_library(vhsm_crypto_provider INTERFACE)
    target_link_libraries(vhsm_crypto_provider INTERFACE vhsm_secure_crypto)
    target_include_directories(vhsm_crypto_provider INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/vhsm-secure-crypto/include)
    target_compile_definitions(vhsm_crypto_provider INTERFACE VHSM_USE_SECURE_CRYPTO VHSM_OPENSSL_SHIM=1)
    add_compile_definitions(VHSM_USE_SECURE_CRYPTO)
    message(STATUS "VHSM: using vhsm-secure-crypto (hardened clone) via vhsm_crypto_provider — symmetric primitives (AES/GCM/SHA/HMAC/PBKDF2/HKDF/DRBG) from the clone; RSA/EC key operations still use system OpenSSL for bignum math")
else()
    find_package(OpenSSL REQUIRED)
    # Compatibility: provide provider alias to OpenSSL when not using secure clone
    add_library(vhsm_crypto_provider INTERFACE)
    target_link_libraries(vhsm_crypto_provider INTERFACE OpenSSL::Crypto OpenSSL::SSL)
endif()

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
# Compatibility shim: system FindSQLite3 before CMake 4.3 provides only
# SQLite::SQLite3, 4.3+ provides SQLite3::SQLite3 (+ deprecated alias).
# Provide the missing alias so both spellings work on any runner
# (Linux apt CMake 3.28 vs Windows vcpkg CMake 4.x) and handle vcpkg's
# unofficial package name.
if(TARGET SQLite::SQLite3 AND NOT TARGET SQLite3::SQLite3)
  add_library(SQLite3::SQLite3 ALIAS SQLite::SQLite3)
endif()
if(TARGET SQLite3::SQLite3 AND NOT TARGET SQLite::SQLite3)
  add_library(SQLite::SQLite3 ALIAS SQLite3::SQLite3)
endif()
if(NOT TARGET SQLite::SQLite3 AND NOT TARGET SQLite3::SQLite3)
  if(TARGET unofficial::SQLite3::SQLite3)
    add_library(SQLite::SQLite3 ALIAS unofficial::SQLite3::SQLite3)
    add_library(SQLite3::SQLite3 ALIAS unofficial::SQLite3::SQLite3)
  elseif(TARGET unofficial::sqlite3::sqlite3)
    add_library(SQLite::SQLite3 ALIAS unofficial::sqlite3::sqlite3)
    add_library(SQLite3::SQLite3 ALIAS unofficial::sqlite3::sqlite3)
  elseif(SQLite3_FOUND)
    # Fallback: variables only (some Find modules / vcpkg older ports)
    add_library(SQLite::SQLite3 INTERFACE IMPORTED)
    if(SQLite3_INCLUDE_DIRS)
      set_target_properties(SQLite::SQLite3 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${SQLite3_INCLUDE_DIRS}")
    endif()
    if(SQLite3_LIBRARIES)
      set_target_properties(SQLite::SQLite3 PROPERTIES INTERFACE_LINK_LIBRARIES "${SQLite3_LIBRARIES}")
    elseif(SQLITE3_LIBRARY)
      set_target_properties(SQLite::SQLite3 PROPERTIES INTERFACE_LINK_LIBRARIES "${SQLITE3_LIBRARY}")
    endif()
    add_library(SQLite3::SQLite3 ALIAS SQLite::SQLite3)
  endif()
endif()
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
    set(DB_LIBRARIES    SQLite3::SQLite3)         # shim above ensures it exists on CMake <4.3
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
    VHSM_STORE_BACKEND_${VHSM_STORE_BACKEND}    # e.g. VHSM_STORE_BACKEND_db
    $<$<BOOL:${VHSM_ASYNC_DB}>:VHSM_ASYNC_DB>
    $<$<BOOL:${VHSM_REQUIRE_DB}>:VHSM_REQUIRE_DB>
    $<$<BOOL:${VHSM_ADMIN_GRPC}>:VHSM_ADMIN_GRPC>
    $<$<BOOL:${VHSM_NOTIFY_EMAIL}>:VHSM_NOTIFY_EMAIL>
    $<$<BOOL:${VHSM_NOTIFY_WEBHOOK}>:VHSM_NOTIFY_WEBHOOK>
    $<$<BOOL:${VHSM_LEDGER}>:VHSM_LEDGER>
    VHSM_NOTIFY_BUS_SIZE=${VHSM_NOTIFY_BUS_SIZE}
)

# ---------------------------------------------------------------------------
# Subdirectories
# ---------------------------------------------------------------------------

enable_testing()  # Enable CTest for the tests/ subdirectory

# Fabric Gateway C++ SDK (gRPC transport + Gateway client).  Pulled in when the
# ledger integration is built (controlled by the VHSM_LEDGER option below).
option(VHSM_LEDGER "Build the Fabric ledger signature anchor integration" ON)
if(VHSM_LEDGER)
    add_subdirectory(third_party/fabric-gateway-cpp)
endif()

add_subdirectory(src)
add_subdirectory(tests)

option(VHSM_BUILD_EXAMPLES "Build PKCS#11 usage examples" OFF)
if(VHSM_BUILD_EXAMPLES)
  add_subdirectory(examples/pkcs11)
endif()

# Throughput benchmark: -DVHSM_ENABLE_BENCH=ON builds tests/bench/vhsm_bench,
# which drives the real C entry points and reports median ops/sec.
option(VHSM_ENABLE_BENCH "Build PKCS#11 throughput benchmark" OFF)
if(VHSM_ENABLE_BENCH)
    add_subdirectory(tests/bench)
endif()
# add_subdirectory(tools)

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
install(DIRECTORY include/ DESTINATION include)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/generated/vhsm/version.h DESTINATION include/vhsm)

# Version info for downstream find_package
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/VirtualHSMConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/VirtualHSMConfigVersion.cmake"
        DESTINATION lib/cmake/VirtualHSM)
