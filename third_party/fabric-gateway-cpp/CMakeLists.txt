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

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})

# Library sources
set(SOURCES
    gateway.cpp
    network.cpp
    contract.cpp
    query.cpp
    src/fabric/crypto/ec.cpp
    src/fabric/crypto/csr.cpp
    src/fabric/crypto/x509.cpp
    src/fabric/identity/wallet.cpp
)

# Create library
add_library(fabric-gateway-cpp STATIC ${SOURCES})

# Link libraries
target_link_libraries(fabric-gateway-cpp PRIVATE CURL::libcurl OpenSSL::Crypto)

# Install headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ DESTINATION include/fabric-gateway-cpp FILES_MATCHING PATTERN "*.h")

# Install library
install(TARGETS fabric-gateway-cpp DESTINATION lib)