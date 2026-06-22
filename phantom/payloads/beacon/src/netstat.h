#pragma once

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fstream>
#endif
#include <string>
#include <vector>
#include <sstream>
#include <cstring>

namespace netstat {

#ifdef _WIN32

struct ConnEntry {
    std::string protocol;
    std::string localAddr;
    int localPort;
    std::string remoteAddr;
    int remotePort;
    std::string state;
    DWORD pid;
    std::string processName;
};

inline std::string tcp_state(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED:     return "CLOSED";
        case MIB_TCP_STATE_LISTEN:     return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:      return "ESTAB";
        case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:    return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        default:                       return "UNKNOWN";
    }
}

inline std::string pid_to_name(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return std::to_string(pid);
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) { CloseHandle(snap); return std::to_string(pid); }
    do {
        if (pe.th32ProcessID == pid) {
            char name[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, name, sizeof(name), nullptr, nullptr);
            CloseHandle(snap);
            return std::string(name);
        }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return std::to_string(pid);
}

inline std::vector<ConnEntry> get_tcp_connections() {
    std::vector<ConnEntry> results;

    HMODULE hIphlpapi = LoadLibraryA("iphlpapi.dll");
    if (!hIphlpapi) return results;

    auto pGetExtendedTcpTable = (DWORD(WINAPI*)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG))
        GetProcAddress(hIphlpapi, "GetExtendedTcpTable");
    if (!pGetExtendedTcpTable) { FreeLibrary(hIphlpapi); return results; }

    ULONG size = 0;
    pGetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) { FreeLibrary(hIphlpapi); return results; }

    std::vector<char> buf(size);
    PMIB_TCPTABLE_OWNER_PID tcpTable = (PMIB_TCPTABLE_OWNER_PID)buf.data();

    if (pGetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        FreeLibrary(hIphlpapi);
        return results;
    }

    for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID& row = tcpTable->table[i];
        ConnEntry e;
        e.protocol = "TCP";
        struct in_addr addr;
        addr.S_un.S_addr = row.dwLocalAddr;
        e.localAddr = inet_ntoa(addr);
        e.localPort = ntohs((u_short)row.dwLocalPort);
        addr.S_un.S_addr = row.dwRemoteAddr;
        e.remoteAddr = inet_ntoa(addr);
        e.remotePort = ntohs((u_short)row.dwRemotePort);
        e.state = tcp_state(row.dwState);
        e.pid = row.dwOwningPid;
        e.processName = pid_to_name(row.dwOwningPid);
        results.push_back(e);
    }

    FreeLibrary(hIphlpapi);
    return results;
}

#else

struct ConnEntry {
    std::string protocol;
    std::string localAddr;
    int localPort;
    std::string remoteAddr;
    int remotePort;
    std::string state;
    int pid;
    std::string processName;
};

inline std::string tcp_state_linux(int state) {
    switch (state) {
        case 0x01: return "ESTAB";
        case 0x02: return "SYN_SENT";
        case 0x03: return "SYN_RCVD";
        case 0x04: return "FIN_WAIT1";
        case 0x05: return "FIN_WAIT2";
        case 0x06: return "TIME_WAIT";
        case 0x07: return "CLOSE";
        case 0x08: return "CLOSE_WAIT";
        case 0x09: return "LAST_ACK";
        case 0x0A: return "LISTEN";
        case 0x0B: return "CLOSING";
        default:   return "UNKNOWN";
    }
}

inline std::string hex_to_ip(const std::string& hex) {
    unsigned int ip[4];
    if (sscanf(hex.c_str(), "%02x%02x%02x%02x", &ip[3], &ip[2], &ip[1], &ip[0]) >= 4) {
        return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "."
             + std::to_string(ip[2]) + "." + std::to_string(ip[3]);
    }
    return "0.0.0.0";
}

inline int hex_to_port(const std::string& hex) {
    unsigned int p;
    sscanf(hex.c_str(), "%04x", &p);
    return p;
}

inline std::string pid_to_name(int pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/comm";
    FILE* f = fopen(path.c_str(), "r");
    if (!f) return std::to_string(pid);
    char comm[256];
    std::string name;
    if (fgets(comm, sizeof(comm), f)) {
        size_t len = strlen(comm);
        if (len > 0 && comm[len-1] == '\n') comm[len-1] = '\0';
        name = comm;
    }
    fclose(f);
    return name.empty() ? std::to_string(pid) : name;
}

inline std::vector<ConnEntry> get_tcp_connections() {
    std::vector<ConnEntry> results;

    // Read /proc/net/tcp
    FILE* f = fopen("/proc/net/tcp", "r");
    if (!f) return results;

    char line[512];
    // Skip header
    if (!fgets(line, sizeof(line), f)) { fclose(f); return results; }

    while (fgets(line, sizeof(line), f)) {
        ConnEntry e;
        e.protocol = "TCP";

        unsigned int state;
        unsigned long txq, rxq, tr, tmWhen, retr, uid, timeout, inode;
        char localHex[32], remoteHex[32];

        int n = sscanf(line, "%*d: %31[0-9A-Fa-f]:%4x %31[0-9A-Fa-f]:%4x %2x %lx:%lx %lx:%lx %lx %*d %*d %lu %*s",
            localHex, &e.localPort, remoteHex, &e.remotePort,
            &state, &txq, &rxq, &tr, &tmWhen, &retr, &inode);
        if (n < 11) continue;

        (void)txq; (void)rxq; (void)tr; (void)tmWhen; (void)retr; (void)uid; (void)timeout;

        e.localAddr = hex_to_ip(localHex);
        e.remoteAddr = hex_to_ip(remoteHex);
        e.state = tcp_state_linux(state);

        // Map inode to PID by scanning /proc/<pid>/fd/<n>
        e.pid = 0;
        DIR* proc = opendir("/proc");
        if (proc) {
            struct dirent* entry;
            while ((entry = readdir(proc)) != nullptr) {
                bool isNum = true;
                for (char* p = entry->d_name; *p; p++) {
                    if (*p < '0' || *p > '9') { isNum = false; break; }
                }
                if (!isNum) continue;

                std::string fdDir = std::string("/proc/") + entry->d_name + "/fd";
                DIR* fd = opendir(fdDir.c_str());
                if (!fd) continue;

                struct dirent* fdEntry;
                while ((fdEntry = readdir(fd)) != nullptr) {
                    char link[256];
                    std::string fdPath = fdDir + "/" + fdEntry->d_name;
                    ssize_t len = readlink(fdPath.c_str(), link, sizeof(link) - 1);
                    if (len > 0) {
                        link[len] = '\0';
                        char targetInode[32];
                        // Match "socket:[inode]" format
                        unsigned long sockInode = 0;
                        if (sscanf(link, "socket:[%lu]", &sockInode) == 1 && sockInode == inode) {
                            e.pid = static_cast<int>(std::atol(entry->d_name));
                            closedir(fd);
                            goto found_pid;
                        }
                    }
                }
                closedir(fd);
            }
            found_pid:
            closedir(proc);
        }

        e.processName = e.pid > 0 ? pid_to_name(e.pid) : "-";
        results.push_back(e);
    }

    fclose(f);
    return results;
}

#endif

inline std::string format_connections() {
    auto entries = get_tcp_connections();
    if (entries.empty()) return "No active TCP connections found.";

    std::ostringstream out;
    out << "Proto  Local Address           Remote Address          State        PID  Process\n";
    out << "------+-----------------------+-----------------------+------------+-----+---------------------------\n";
    for (const auto& e : entries) {
        char line[512];
        char local[24], remote[24];
        snprintf(local, sizeof(local), "%s:%d", e.localAddr.c_str(), e.localPort);
        snprintf(remote, sizeof(remote), "%s:%d", e.remoteAddr.c_str(), e.remotePort);
        snprintf(line, sizeof(line), "%-6s %-22s %-22s %-11s %5d %s\n",
                 e.protocol.c_str(), local, remote, e.state.c_str(), e.pid, e.processName.c_str());
        out << line;
    }
    return out.str();
}

inline std::string format_connections_json() {
    auto entries = get_tcp_connections();
    if (entries.empty()) return "CONNECTIONS:[]";

    std::ostringstream out;
    out << "CONNECTIONS:[";
    for (size_t i = 0; i < entries.size(); i++) {
        if (i > 0) out << ",";
        std::string procEscaped;
        for (char c : entries[i].processName) {
            if (c == '"') procEscaped += "\\\"";
            else if (c == '\\') procEscaped += "\\\\";
            else procEscaped += c;
        }
        out << "{\"proto\":\"" << entries[i].protocol
            << "\",\"local\":\"" << entries[i].localAddr << ":" << entries[i].localPort
            << "\",\"remote\":\"" << entries[i].remoteAddr << ":" << entries[i].remotePort
            << "\",\"state\":\"" << entries[i].state
            << "\",\"pid\":" << entries[i].pid
            << ",\"proc\":\"" << procEscaped << "\"}";
    }
    out << "]";
    return out.str();
}

} // namespace netstat
