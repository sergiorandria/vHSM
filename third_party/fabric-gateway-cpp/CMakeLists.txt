cmake_minimum_required(VERSION 3.21)
project(fabric-gateway-cpp LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find libcurl
find_package(CURL REQUIRED)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Find nlohmann_json
find_package(nlohmann_json 3.2.0 REQUIRED)

# Testing (BUILD_TESTING off by default unless CTest is included)
include(CTest)

# Header locations
set(FABRIC_SDK_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(FABRIC_SDK_ROOT_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# Library sources — the src/fabric tree is the canonical implementation.
set(SOURCES
    src/fabric/crypto/ec.cpp
    src/fabric/crypto/csr.cpp
    src/fabric/crypto/x509.cpp
    src/fabric/crypto/client_tls_config.cpp
    src/fabric/identity/wallet.cpp
    src/fabric/identity/identity.cpp
    src/fabric/ca/httpclient.cpp
    src/fabric/ca/ca_client.cpp
)

# Create library
add_library(fabric-gateway-cpp STATIC ${SOURCES})

target_include_directories(fabric-gateway-cpp
    PUBLIC  ${FABRIC_SDK_INCLUDE_DIR}
)

# ec.cpp uses the pre-OpenSSL-3 ECDSA_* API for legacy-compat signing;
# silence the deprecation warnings so the SDK builds -Werror-clean.
target_compile_definitions(fabric-gateway-cpp PRIVATE OPENSSL_SUPPRESS_DEPRECATED)

# Link libraries
target_link_libraries(fabric-gateway-cpp
    PUBLIC
        CURL::libcurl
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
)

# Install headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION include)
install(TARGETS fabric-gateway-cpp DESTINATION lib)

if(BUILD_TESTING)
    # Smoke test: CaClient + CurlHttpClient construction
    add_executable(fabric_gateway_cpp_smoke_test tests/test_ca_client.cpp)
    target_include_directories(fabric_gateway_cpp_smoke_test PRIVATE ${FABRIC_SDK_INCLUDE_DIR})
    target_link_libraries(fabric_gateway_cpp_smoke_test PRIVATE fabric-gateway-cpp)
    add_test(NAME fabric_gateway_cpp_smoke_test COMMAND fabric_gateway_cpp_smoke_test)

    # Phase 1 unit tests: keygen, CSR, sign/verify round-trip, identity, wallet
    find_package(GTest REQUIRED)
    add_executable(fabric_gateway_cpp_unit_tests tests/test_crypto.cpp)
    target_include_directories(fabric_gateway_cpp_unit_tests PRIVATE ${FABRIC_SDK_INCLUDE_DIR})
    target_link_libraries(fabric_gateway_cpp_unit_tests PRIVATE fabric-gateway-cpp GTest::gtest_main)
    add_test(NAME fabric_gateway_cpp_unit_tests COMMAND fabric_gateway_cpp_unit_tests)
endif()