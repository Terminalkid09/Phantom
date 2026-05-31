cmake_minimum_required(VERSION 3.15)
project(PhantomBeacon LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
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
    target_link_libraries(beacon PRIVATE winhttp bcrypt ws2_32)
    if(MSVC)
        set_target_properties(beacon PROPERTIES LINK_FLAGS_RELEASE "/SUBSYSTEM:WINDOWS")
    endif()
else()
    # POSIX (Linux, macOS, Android)
    find_package(CURL REQUIRED)
    find_package(OpenSSL REQUIRED)
    find_package(Threads REQUIRED)

    target_include_directories(beacon PRIVATE ${CURL_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(beacon PRIVATE ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES} Threads::Threads)
    
    if(APPLE)
        find_library(CORE_GRAPHICS CoreGraphics)
        target_link_libraries(beacon PRIVATE ${CORE_GRAPHICS})
    endif()
endif()
