cmake_minimum_required(VERSION 3.15)
project(PhantomBeacon LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Release optimizations ─────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(MSVC)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /GL /GS- /MT")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG /OPT:REF /OPT:ICF")
elseif(MINGW OR CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -s")
    if(MINGW)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")
    endif()
endif()

# ── Source files ──────────────────────────────────────────────────────────
if(WIN32)
    add_executable(beacon WIN32 src/main.cpp)
else()
    add_executable(beacon src/main.cpp)
endif()

# ── Link libraries ────────────────────────────────────────────────────────
if(WIN32)
    # Windows native - zero external deps
    target_link_libraries(beacon PRIVATE winhttp bcrypt ws2_32 bthprops wlanapi iphlpapi)
    if(MSVC)
        set_target_properties(beacon PROPERTIES LINK_FLAGS_RELEASE "/SUBSYSTEM:WINDOWS")
    endif()
else()
    # POSIX (Linux, macOS, Android)
    # Prefer static libraries when available
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a .so)
    set(BUILD_STATIC TRUE)   # custom flag we can toggle from the command line

    find_package(CURL REQUIRED)
    find_package(OpenSSL REQUIRED)
    find_package(Threads REQUIRED)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(NGHTTP2 REQUIRED libnghttp2)
    pkg_check_modules(BROTLI REQUIRED libbrotlidec libbrotlienc)
    pkg_check_modules(GSSAPI REQUIRED gssapi_krb5)

    target_include_directories(beacon PRIVATE ${CURL_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR} ${NGHTTP2_INCLUDE_DIRS} ${BROTLI_INCLUDE_DIRS} ${GSSAPI_INCLUDE_DIRS})

    # Force static linking of the C/C++ runtime
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")

    # System libs required for a fully static binary
    set(STATIC_SYSTEM_LIBS -pthread -lrt -ldl -lcrypt -lresolv)

    target_link_libraries(beacon PRIVATE ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES} ${NGHTTP2_LIBRARIES} ${BROTLI_LIBRARIES} ${GSSAPI_LIBRARIES}
        Threads::Threads ${STATIC_SYSTEM_LIBS})

    if(APPLE)
        find_library(CORE_GRAPHICS CoreGraphics)
        target_link_libraries(beacon PRIVATE ${CORE_GRAPHICS})
    endif()
endif()
