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

namespace proxy {

inline void socks5_relay(SOCKET a, SOCKET b, std::atomic<bool>& running) {
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

inline bool socks5_handshake(SOCKET s, std::string& targetHost, int& targetPort) {
    unsigned char buf[1024];
    int n = recv(s, (char*)buf, sizeof(buf), 0);
    if (n < 2 || buf[0] != 5) return false;
    if (n < 2 + buf[1]) return false;
    unsigned char authResp[] = {5, 0};
    send(s, (const char*)authResp, 2, 0);

    n = recv(s, (char*)buf, sizeof(buf), 0);
    if (n < 7 || buf[0] != 5 || buf[1] != 1) return false;

    int atyp = buf[3];
    int addrLen = 0;
    if (atyp == 1) {
        addrLen = 4;
    } else if (atyp == 3) {
        addrLen = 1 + buf[4];
    } else if (atyp == 4) {
        addrLen = 16;
    } else {
        return false;
    }
    if (n < 4 + addrLen + 2) return false;

    if (atyp == 1) {
        unsigned char* ip = buf + 4;
        targetHost = std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "."
                   + std::to_string(ip[2]) + "." + std::to_string(ip[3]);
    } else if (atyp == 3) {
        targetHost.assign((char*)(buf + 5), buf[4]);
    } else if (atyp == 4) {
        char ipv6Str[48];
        inet_ntop(AF_INET6, buf + 4, ipv6Str, sizeof(ipv6Str));
        targetHost = ipv6Str;
    }

    targetPort = (buf[4 + addrLen] << 8) | buf[5 + addrLen];

    unsigned char resp[] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
    send(s, (const char*)resp, 10, 0);
    return true;
}

struct Socks5Proxy {
    int localPort;
    std::atomic<bool> running{false};
    std::thread thread;

    void start() {
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
#else
        int flags = fcntl(listenSock, F_GETFL, 0);
        fcntl(listenSock, F_SETFL, flags | O_NONBLOCK);
#endif
        while (running) {
            SOCKET clientSock = accept(listenSock, nullptr, nullptr);
            if (clientSock == INVALID_SOCKET) { Sleep(100); continue; }

            std::thread([this, clientSock]() {
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
                socks5_relay(clientSock, remoteSock, this->running);
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
