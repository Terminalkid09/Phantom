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
#include <sys/wait.h>
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
#include <vector>
#include <thread>
#include <atomic>
#include <sstream>
#include <cstring>
#include <cstdio>
#include <cstdlib>

namespace cdp_pivot {

inline std::string json_get_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    std::string result;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) { pos++; }
        result += json[pos++];
    }
    return result;
}

inline int json_get_int(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return 0;
    pos += search.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    bool neg = (pos < json.size() && json[pos] == '-');
    if (neg) pos++;
    int v = 0;
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
        v = v * 10 + (json[pos++] - '0');
    }
    return neg ? -v : v;
}

struct WsConnection {
    SOCKET sock = INVALID_SOCKET;
    bool connected = false;
    char key_buf[32];

    bool connect_http(const std::string& host, int port, const std::string& path) {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return false;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons((u_short)port);

        struct hostent* he = gethostbyname(host.c_str());
        if (!he) { closesocket(sock); sock = INVALID_SOCKET; return false; }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
            closesocket(sock); sock = INVALID_SOCKET; return false;
        }

        for (int i = 0; i < 16; i++) key_buf[i] = (char)(rand() % 256);
        std::string wsKey;
        for (int i = 0; i < 24; i += 3) {
            int v = ((unsigned char)key_buf[i] << 16) | (unsigned char)key_buf[i+1] << 8 | (unsigned char)key_buf[i+2];
            static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            wsKey += b64[(v >> 18) & 0x3F];
            wsKey += b64[(v >> 12) & 0x3F];
            wsKey += b64[(v >> 6) & 0x3F];
            wsKey += b64[v & 0x3F];
        }

        std::string req = "GET " + path + " HTTP/1.1\r\n"
                          "Host: " + host + ":" + std::to_string(port) + "\r\n"
                          "Upgrade: websocket\r\n"
                          "Connection: Upgrade\r\n"
                          "Sec-WebSocket-Key: " + wsKey + "\r\n"
                          "Sec-WebSocket-Version: 13\r\n"
                          "\r\n";
        send(sock, req.c_str(), (int)req.size(), 0);

        char resp[4096];
        int n = recv(sock, resp, sizeof(resp) - 1, 0);
        if (n <= 0) { closesocket(sock); sock = INVALID_SOCKET; return false; }
        resp[n] = 0;

        if (std::string(resp).find("101") == std::string::npos) {
            closesocket(sock); sock = INVALID_SOCKET; return false;
        }
        connected = true;
        return true;
    }

    bool send_frame(const std::string& payload) {
        if (!connected || sock == INVALID_SOCKET) return false;

        std::vector<unsigned char> frame;
        frame.push_back(0x81);

        size_t len = payload.size();
        unsigned char maskKey[4];
        for (int i = 0; i < 4; i++) maskKey[i] = (unsigned char)(rand() % 256);

        if (len < 126) {
            frame.push_back((unsigned char)(0x80 | len));
        } else if (len < 65536) {
            frame.push_back(0x80 | 126);
            frame.push_back((unsigned char)((len >> 8) & 0xFF));
            frame.push_back((unsigned char)(len & 0xFF));
        } else {
            frame.push_back(0x80 | 127);
            for (int i = 7; i >= 0; i--) frame.push_back((unsigned char)((len >> (i * 8)) & 0xFF));
        }

        for (int i = 0; i < 4; i++) frame.push_back(maskKey[i]);

        for (size_t i = 0; i < len; i++) {
            frame.push_back((unsigned char)(payload[i] ^ maskKey[i % 4]));
        }

        return send(sock, (const char*)frame.data(), (int)frame.size(), 0) > 0;
    }

    std::string recv_frame(int timeoutMs = 30000) {
        if (!connected || sock == INVALID_SOCKET) return "";

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        timeval tv = {timeoutMs / 1000, (int)(timeoutMs % 1000) * 1000};
#ifdef _WIN32
        int sel = select(0, &fds, nullptr, nullptr, &tv);
#else
        int sel = select(sock + 1, &fds, nullptr, nullptr, &tv);
#endif
        if (sel <= 0) return "";

        unsigned char header[2];
        int n = recv(sock, (char*)header, 2, MSG_PEEK);
        if (n < 2) return "";

        unsigned char opcode = header[0] & 0x0F;
        bool masked = (header[1] & 0x80) != 0;
        uint64_t payloadLen = header[1] & 0x7F;

        if (payloadLen == 126) {
            unsigned char ext[2];
            if (recv(sock, (char*)ext, 2, MSG_PEEK | MSG_WAITALL) < 2) return "";
            payloadLen = ((uint64_t)ext[0] << 8) | ext[1];
        } else if (payloadLen == 127) {
            unsigned char ext[8];
            if (recv(sock, (char*)ext, 8, MSG_PEEK) < 8) return "";
            payloadLen = 0;
            for (int i = 0; i < 8; i++) payloadLen = (payloadLen << 8) | ext[i];
        }

        unsigned char maskKey[4] = {0};
        size_t extraHeader = (header[1] & 0x7F) == 126 ? 4 : (header[1] & 0x7F) == 127 ? 10 : 2;
        if (masked) extraHeader += 4;

        size_t total = extraHeader + (size_t)payloadLen;
        if (total > 1024 * 1024) return "";

        std::vector<unsigned char> frame(total);
        n = recv(sock, (char*)frame.data(), (int)total, MSG_WAITALL);
        if ((size_t)n < total) return "";

        size_t pos = 2;
        if (payloadLen == 126) pos = 4;
        else if (payloadLen == 127) pos = 10;

        if (masked) {
            maskKey[0] = frame[pos];
            maskKey[1] = frame[pos + 1];
            maskKey[2] = frame[pos + 2];
            maskKey[3] = frame[pos + 3];
            pos += 4;
        }

        std::string result((const char*)frame.data() + pos, (size_t)payloadLen);
        if (masked) {
            for (size_t i = 0; i < payloadLen; i++) {
                result[i] = result[i] ^ maskKey[i % 4];
            }
        }

        if (opcode == 8) { connected = false; return ""; }
        if (opcode == 9) return "";
        return result;
    }

    void ws_close() {
        connected = false;
        if (sock != INVALID_SOCKET) { closesocket(sock); sock = INVALID_SOCKET; }
    }
};

#ifdef _WIN32
inline void kill_chrome() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) { CloseHandle(snap); return; }
    do {
        char name[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, name, sizeof(name), nullptr, nullptr);
        if (_stricmp(name, "chrome.exe") == 0) {
            HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
            if (hProc) { TerminateProcess(hProc, 1); CloseHandle(hProc); }
        }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    Sleep(500);
}

inline bool launch_chrome_with_debug(int port) {
    kill_chrome();
    Sleep(200);

    const char* appData = getenv("LOCALAPPDATA");
    if (!appData) return false;
    std::string userData = std::string(appData) + "\\Google\\Chrome\\User Data";

    std::string cmdline = "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" "
        "--remote-debugging-port=" + std::to_string(port) + " "
        "--user-data-dir=\"" + userData + "\" "
        "--no-first-run --no-default-browser-check --no-sandbox";

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, &cmdline[0], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}
#else
inline void kill_chrome() {
    // Kill existing Chrome processes
    int r = system("pkill -9 chrome 2>/dev/null; pkill -9 chromium 2>/dev/null; pkill -9 chromium-browser 2>/dev/null");
    (void)r;
    usleep(500000);
}

inline bool launch_chrome_with_debug(int port) {
    kill_chrome();
    usleep(200000);
    const char* home = getenv("HOME");
    if (!home) return false;
    std::string userData = std::string(home) + "/.config/google-chrome-PhantomCDP";
    std::string cmd = "google-chrome --remote-debugging-port=" + std::to_string(port) +
        " --user-data-dir=\"" + userData + "\""
        " --no-first-run --no-default-browser-check --no-sandbox --disable-gpu"
        " >/dev/null 2>&1 &";
    int r = system(cmd.c_str());
    return r == 0;
}
#endif

inline std::string http_get(const std::string& host, int port, const std::string& path) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return "";

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    struct hostent* he = gethostbyname(host.c_str());
    if (!he) { closesocket(s); return ""; }
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) { closesocket(s); return ""; }

    std::string req = "GET " + path + " HTTP/1.1\r\n"
                      "Host: " + host + ":" + std::to_string(port) + "\r\n"
                      "Connection: close\r\n\r\n";
    send(s, req.c_str(), (int)req.size(), 0);

    std::string resp;
    char buf[4096];
    int n;
    while ((n = recv(s, buf, sizeof(buf), 0)) > 0) resp.append(buf, n);
    closesocket(s);

    size_t hdrEnd = resp.find("\r\n\r\n");
    if (hdrEnd == std::string::npos) return resp;
    return resp.substr(hdrEnd + 4);
}

struct CdpSession {
    WsConnection ws;
    int msgId = 1;
    bool ready = false;
    std::string targetId;
    std::string targetUrl;
    std::string lastResult;

    bool connect(int port = 9222) {
        std::string versionInfo = http_get("127.0.0.1", port, "/json/version");
        if (versionInfo.empty()) return false;

        std::string wsUrl = json_get_string(versionInfo, "webSocketDebuggerUrl");
        if (wsUrl.empty()) {
            std::string listInfo = http_get("127.0.0.1", port, "/json");
            if (listInfo.empty()) return false;
            wsUrl = json_get_string(listInfo, "webSocketDebuggerUrl");
            if (wsUrl.empty()) return false;
        }

        std::string host, path;
        int wsPort = port;
        if (wsUrl.find("ws://") == 0) {
            std::string rest = wsUrl.substr(5);
            size_t colon = rest.find(':');
            size_t slash = rest.find('/');
            if (colon != std::string::npos && colon < slash) {
                host = rest.substr(0, colon);
                wsPort = std::stoi(rest.substr(colon + 1, slash - colon - 1));
                path = rest.substr(slash);
            } else if (slash != std::string::npos) {
                host = rest.substr(0, slash);
                path = rest.substr(slash);
            } else {
                host = rest;
                path = "/";
            }
        }

        if (!ws.connect_http(host, wsPort, path)) return false;
        ready = true;
        return true;
    }

    std::string send_command(const std::string& method, const std::string& params = "{}") {
        if (!ready) return "";
        int id = msgId++;
        std::string cmd = "{\"id\":" + std::to_string(id) + ",\"method\":\"" + method + "\",\"params\":" + params + "}";
        if (!ws.send_frame(cmd)) return "";

        int timeout = 0;
        while (timeout < 300) {
            std::string resp = ws.recv_frame(1000);
            if (resp.empty()) { timeout += 1; continue; }

            std::string respIdStr = "\"id\":" + std::to_string(id);
            if (resp.find(respIdStr) != std::string::npos) {
                lastResult = resp;
                return resp;
            }
            if (resp.find("\"method\":\"Target.targetCreated\"") != std::string::npos) {
                std::string tInfo = json_get_string(resp, "targetInfo");
                if (!tInfo.empty()) {
                    std::string tid = json_get_string(tInfo, "targetId");
                    std::string url = json_get_string(tInfo, "url");
                    if (!tid.empty() && !url.empty()) {
                        targetId = tid;
                        targetUrl = url;
                    }
                }
            }
        }
        return "";
    }

    std::string evaluate(const std::string& expression) {
        std::string escaped;
        for (char c : expression) {
            if (c == '"') escaped += "\\\"";
            else if (c == '\\') escaped += "\\\\";
            else if (c == '\n') escaped += "\\n";
            else if (c == '\r') escaped += "\\r";
            else if (c == '\t') escaped += "\\t";
            else escaped += c;
        }
        std::string params = "{\"expression\":\"" + escaped + "\",\"returnByValue\":true}";
        std::string resp = send_command("Runtime.evaluate", params);
        if (resp.empty()) return "";
        std::string result = json_get_string(resp, "result");
        if (result.empty()) {
            size_t valPos = resp.find("\"value\":\"");
            if (valPos != std::string::npos) {
                valPos += 9;
                std::string val;
                while (valPos < resp.size() && resp[valPos] != '"') {
                    if (resp[valPos] == '\\' && valPos + 1 < resp.size()) valPos++;
                    val += resp[valPos++];
                }
                return val;
            }
            valPos = resp.find("\"value\":");
            if (valPos != std::string::npos) {
                valPos += 8;
                while (valPos < resp.size() && (resp[valPos] == ' ' || resp[valPos] == '\t')) valPos++;
                if (resp[valPos] == '"') {
                    valPos++;
                    std::string val;
                    while (valPos < resp.size() && resp[valPos] != '"') {
                        if (resp[valPos] == '\\' && valPos + 1 < resp.size()) valPos++;
                        val += resp[valPos++];
                    }
                    return val;
                }
                std::string val;
                while (valPos < resp.size() && (resp[valPos] >= '0' && resp[valPos] <= '9' || resp[valPos] == '-')) {
                    val += resp[valPos++];
                }
                return val;
            }
        }
        return result;
    }

    void disconnect() {
        ready = false;
        ws.ws_close();
    }
};

inline std::string launch_and_connect(int port = 9222) {
    if (!launch_chrome_with_debug(port)) return "Failed to launch Chrome with remote debugging.";
    Sleep(2000);

    CdpSession session;
    if (!session.connect(port)) return "Chrome launched but CDP connection failed.";
    session.disconnect();
    return "Chrome CDP session ready on port " + std::to_string(port) + ".";
}

inline std::string cdp_cookies(int port = 9222) {
    CdpSession session;
    if (!session.connect(port)) return "CDP connection failed. Ensure Chrome is running with --remote-debugging-port=" + std::to_string(port);

    std::string resp = session.send_command("Network.getAllCookies");
    session.disconnect();

    if (resp.empty()) return "Failed to get cookies via CDP.";

    std::string result;
    size_t pos = 0;
    int count = 0;
    while (true) {
        size_t namePos = resp.find("\"name\":\"", pos);
        if (namePos == std::string::npos) break;
        namePos += 8;
        std::string name;
        while (namePos < resp.size() && resp[namePos] != '"') {
            if (resp[namePos] == '\\') namePos++;
            name += resp[namePos++];
        }

        size_t valPos = resp.find("\"value\":\"", namePos);
        if (valPos == std::string::npos) break;
        valPos += 9;
        std::string value;
        while (valPos < resp.size() && resp[valPos] != '"') {
            if (resp[valPos] == '\\') valPos++;
            value += resp[valPos++];
        }

        size_t domainPos = resp.find("\"domain\":\"", valPos);
        if (domainPos == std::string::npos) break;
        domainPos += 10;
        std::string domain;
        while (domainPos < resp.size() && resp[domainPos] != '"') domain += resp[domainPos++];

        result += "Domain: " + domain + "\n";
        result += "  " + name + " = " + value + "\n";
        pos = domainPos;
        count++;
    }

    if (count == 0) return "No cookies found via CDP.";

    return "=== CDP COOKIES (" + std::to_string(count) + ") ===\n" + result;
}

inline std::string cdp_evaluate(const std::string& expression, int port = 9222) {
    CdpSession session;
    if (!session.connect(port)) return "CDP connection failed.";

    std::string result = session.evaluate(expression);
    session.disconnect();

    if (result.empty()) return "No result from expression.";
    return result;
}

inline std::string cdp_navigate(const std::string& url, int port = 9222) {
    CdpSession session;
    if (!session.connect(port)) return "CDP connection failed.";

    std::string params = "{\"url\":\"" + url + "\"}";
    std::string resp = session.send_command("Page.navigate", params);
    session.disconnect();

    if (resp.empty()) return "Navigation failed.";
    std::string frameId = json_get_string(resp, "frameId");
    return "Navigated to " + url + " (frame: " + frameId + ")";
}

inline std::string cdp_fetch(const std::string& url, int port = 9222) {
    CdpSession session;
    if (!session.connect(port)) return "CDP connection failed.";

    std::string escapedUrl;
    for (char c : url) {
        if (c == '"') escapedUrl += "\\\"";
        else if (c == '\\') escapedUrl += "\\\\";
        else escapedUrl += c;
    }

    std::string expr = "fetch('" + escapedUrl + "').then(r => r.text())";
    std::string result = session.evaluate(expr);
    session.disconnect();

    if (result.empty()) return "Fetch returned no content.";
    return result;
}

} // namespace cdp_pivot
