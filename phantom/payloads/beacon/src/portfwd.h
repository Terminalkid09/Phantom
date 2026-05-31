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

namespace portfwd {

// Relay data between two sockets until one closes
inline void relay(SOCKET a, SOCKET b, std::atomic<bool>& running) {
    char buf[4096];
    while (running) {
        fd_set readFds;
        FD_ZERO(&readFds);
        FD_SET(a, &readFds);
        FD_SET(b, &readFds);

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int maxFd = static_cast<int>((a > b ? a : b) + 1);
        int sel = select(maxFd, &readFds, nullptr, nullptr, &tv);
        if (sel <= 0) continue;

        if (FD_ISSET(a, &readFds)) {
            int n = recv(a, buf, sizeof(buf), 0);
            if (n <= 0) break;
            send(b, buf, n, 0);
        }
        if (FD_ISSET(b, &readFds)) {
            int n = recv(b, buf, sizeof(buf), 0);
            if (n <= 0) break;
            send(a, buf, n, 0);
        }
    }
}

struct PortForward {
    int           localPort;
    std::string   remoteHost;
    int           remotePort;
    std::atomic<bool> running{false};
    std::thread   thread;

    void start() {
        running = true;
        thread = std::thread([this]() { run(); });
        thread.detach();
    }

    void stop() {
        running = false;
    }

private:
    void run() {
#ifdef _WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

        SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSock == INVALID_SOCKET) { running = false; return; }

        int opt = 1;
        setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

        sockaddr_in bindAddr{};
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_addr.s_addr = INADDR_ANY;
        bindAddr.sin_port = htons(static_cast<u_short>(localPort));

        if (bind(listenSock, (sockaddr*)&bindAddr, sizeof(bindAddr)) == SOCKET_ERROR) {
            closesocket(listenSock);
            running = false;
            return;
        }

        if (listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
            closesocket(listenSock);
            running = false;
            return;
        }

#ifdef _WIN32
        u_long nonBlocking = 1;
        ioctlsocket(listenSock, FIONBIO, &nonBlocking);
#else
        int flags = fcntl(listenSock, F_GETFL, 0);
        fcntl(listenSock, F_SETFL, flags | O_NONBLOCK);
#endif

        while (running) {
            SOCKET clientSock = accept(listenSock, nullptr, nullptr);
            if (clientSock == INVALID_SOCKET) {
                Sleep(100);
                continue;
            }

            addrinfo hints{}, *result = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            std::string portStr = std::to_string(remotePort);
            if (getaddrinfo(remoteHost.c_str(), portStr.c_str(), &hints, &result) != 0) {
                closesocket(clientSock);
                continue;
            }

            SOCKET remoteSock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
            if (remoteSock == INVALID_SOCKET) {
                freeaddrinfo(result);
                closesocket(clientSock);
                continue;
            }

            if (connect(remoteSock, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
                closesocket(remoteSock);
                freeaddrinfo(result);
                closesocket(clientSock);
                continue;
            }
            freeaddrinfo(result);

            // Start relay in a detached thread
            std::thread([this, clientSock, remoteSock]() {
                relay(clientSock, remoteSock, this->running);
                closesocket(clientSock);
                closesocket(remoteSock);
            }).detach();
        }

        closesocket(listenSock);
    }
};

// Active port forwards (managed from command dispatch)
inline std::vector<PortForward*> active_forwards;

inline std::string start_forward(int localPort, const std::string& remoteHost, int remotePort) {
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
