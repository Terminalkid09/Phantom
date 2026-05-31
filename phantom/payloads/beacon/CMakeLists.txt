cmake_minimum_required(VERSION 3.15)
project(PhantomBeacon LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Release optimizations ─────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /GL /GS- /MT")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG /OPT:REF /OPT:ICF")

# For MinGW cross-compilation
if(MINGW)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -s -static")
endif()

# ── Source files ──────────────────────────────────────────────────────────
add_executable(beacon WIN32
    src/main.cpp
)

# ── Link libraries (all Windows native - zero external deps) ─────────────
target_link_libraries(beacon PRIVATE
    winhttp
    bcrypt
    ws2_32
)

# ── Strip symbols in release ─────────────────────────────────────────────
if(MSVC)
    set_target_properties(beacon PROPERTIES
        LINK_FLAGS_RELEASE "/SUBSYSTEM:WINDOWS"
    )
endif()
