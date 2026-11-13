cmake_minimum_required(VERSION 3.22.1)
project(phantom_remote LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Shared core headers: remote_net.h, remote_obf.h, crypto.h, c2_config.h and
# beacon_auth config. ../../../../src resolves to payloads/remote/src at build
# time (the compiler stage copies the tree or sets REMOTE_SRC_DIR explicitly).
if(NOT DEFINED REMOTE_SRC_DIR)
    set(REMOTE_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src")
endif()

add_library(phantom_remote SHARED
    native_bridge.cpp)

target_include_directories(phantom_remote PRIVATE
    ${REMOTE_SRC_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

# OpenSSL for Android (cross-compiled by phantom/utils/build_helper.py
# _install_openssl_android into the NDK sysroot, same as the beacon).
find_library(log-lib log)
find_library(ssl-lib ssl)
find_library(crypto-lib crypto)

target_link_libraries(phantom_remote
    ${ssl-lib}
    ${crypto-lib}
    ${log-lib})
