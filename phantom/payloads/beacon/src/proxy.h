#pragma once
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
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

namespace proxy {

inline void socks5_relay(SOCKET a, SOCKET b, std::shared_ptr<std::atomic<bool>> running) {
    char buf[8192];
    while (!running->load()) {
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

inline bool recv_all(SOCKET s, unsigned char* buf, int len) {
    int got = 0;
    while (got < len) {
        int n = recv(s, (char*)buf + got, len - got, 0);
        if (n <= 0) return false;
        got += n;
    }
    return true;
}

inline bool socks5_handshake(SOCKET s, std::string& targetHost, int& targetPort) {
    // The listening socket is non-blocking (so stop() can be observed) and
    // Winsock makes accepted sockets inherit that mode: a single recv() on a
    // freshly accepted client can return WSAEWOULDBLOCK before the browser's
    // CONNECT request arrives. Live defect 2026-10-19: curl got the method
    // reply and then "Failed to receive SOCKS response" because the request
    // read raced the client and the proxy closed the connection. Put the
    // client socket back in blocking mode with a receive timeout and read
    // exact lengths, tolerating TCP segmentation.
#ifdef _WIN32
    u_long blocking = 0;
    ioctlsocket(s, FIONBIO, &blocking);
    DWORD rcvto = 15000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&rcvto, sizeof(rcvto));
#else
    int fl = fcntl(s, F_GETFL, 0);
    if (fl != -1) fcntl(s, F_SETFL, fl & ~O_NONBLOCK);
    timeval rcvto{15, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &rcvto, sizeof(rcvto));
#endif

    unsigned char hdr[2];
    if (!recv_all(s, hdr, 2) || hdr[0] != 5) return false;
    unsigned char methods[255];
    if (!recv_all(s, methods, hdr[1])) return false;
    unsigned char authResp[] = {5, 0};
    send(s, (const char*)authResp, 2, 0);

    unsigned char req[4];
    if (!recv_all(s, req, 4) || req[0] != 5 || req[1] != 1) return false;

    int atyp = req[3];
    int addrLen = 0;
    if (atyp == 1) {
        addrLen = 4;
    } else if (atyp == 3) {
        unsigned char lenByte = 0;
        if (!recv_all(s, &lenByte, 1)) return false;
        addrLen = 1 + lenByte;
    } else if (atyp == 4) {
        addrLen = 16;
    } else {
        return false;
    }

    unsigned char addr[260];
    if (!recv_all(s, addr, addrLen)) return false;
    unsigned char portBuf[2];
    if (!recv_all(s, portBuf, 2)) return false;

    if (atyp == 1) {
        targetHost = std::to_string(addr[0]) + "." + std::to_string(addr[1]) + "."
                   + std::to_string(addr[2]) + "." + std::to_string(addr[3]);
    } else if (atyp == 3) {
        targetHost.assign((char*)addr + 1, addr[0]);
    } else if (atyp == 4) {
        char ipv6Str[48];
        inet_ntop(AF_INET6, addr, ipv6Str, sizeof(ipv6Str));
        targetHost = ipv6Str;
    }

    targetPort = (portBuf[0] << 8) | portBuf[1];

    unsigned char resp[] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
    send(s, (const char*)resp, 10, 0);
    return true;
}

struct Socks5Proxy {
    int localPort;
    std::shared_ptr<std::atomic<bool>> stop_flag;
    std::thread thread;

    void start() {
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

            // `this` is deliberately not captured: the thread copies what it
            // needs (the socket and the stop flag). Capturing it made clang
            // fail the macOS build with -Werror,-Wunused-lambda-capture.
            std::thread([clientSock, stop_flag = this->stop_flag]() {
                std::string targetHost;
                int targetPort = 0;
                if (!socks5_handshake(clientSock, targetHost, targetPort)) {
                    closesocket(clientSock); return;
                }
                addrinfo hints{}, *result = nullptr;
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_protocol = IPPROTO_TCP;
                std::string portStr = std::to_string(targetPort);
                if (getaddrinfo(targetHost.c_str(), portStr.c_str(), &hints, &result) != 0) {
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
                socks5_relay(clientSock, remoteSock, stop_flag);
                closesocket(clientSock);
                closesocket(remoteSock);
            }).detach();
        }
        closesocket(listenSock);
    }
};

inline std::vector<Socks5Proxy*> active_proxies;

inline std::string start_socks(int localPort) {
    auto* sp = new Socks5Proxy();
    sp->localPort = localPort;
    sp->start();
    active_proxies.push_back(sp);
    return "SOCKS5 proxy started on 0.0.0.0:" + std::to_string(localPort);
}

inline std::string stop_socks() {
    for (auto* sp : active_proxies) {
        sp->stop();
        delete sp;
    }
    active_proxies.clear();
    return "All SOCKS5 proxies stopped.";
}

}  // namespace proxy
