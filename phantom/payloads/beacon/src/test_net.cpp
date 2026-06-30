// Minimal test: check in with C2 server via WinHTTP
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#pragma comment(lib, "winhttp")
#pragma comment(lib, "ws2_32")

int main() {
    WSADATA wsa;
    int ws = WSAStartup(MAKEWORD(2,2), &wsa);
    printf("WSAStartup: %d\n", ws);
    if (ws != 0) return 1;
    
    HINTERNET hSession = WinHttpOpen(L"Test/1.0", 
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    printf("WinHttpOpen: %p (err=%d)\n", hSession, hSession ? 0 : GetLastError());
    if (!hSession) { WSACleanup(); return 1; }
    
    HINTERNET hConnect = WinHttpConnect(hSession, L"127.0.0.1", 8080, 0);
    printf("WinHttpConnect: %p (err=%d)\n", hConnect, hConnect ? 0 : GetLastError());
    if (!hConnect) { WinHttpCloseHandle(hSession); WSACleanup(); return 1; }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/api/v1/ping", 
        NULL, NULL, NULL, 0);
    printf("WinHttpOpenRequest: %p (err=%d)\n", hRequest, hRequest ? 0 : GetLastError());
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); WSACleanup(); return 1; }
    
    WinHttpAddRequestHeaders(hRequest, L"X-Beacon-Id: test-c-program\r\n", 
        (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD);
    
    BOOL sent = WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, NULL);
    printf("WinHttpSendRequest: %d (err=%d)\n", sent, sent ? 0 : GetLastError());
    
    if (sent) {
        BOOL recv = WinHttpReceiveResponse(hRequest, NULL);
        printf("WinHttpReceiveResponse: %d (err=%d)\n", recv, recv ? 0 : GetLastError());
        
        if (recv) {
            DWORD status = 0;
            DWORD statusSize = sizeof(status);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                NULL, &status, &statusSize, NULL);
            printf("HTTP Status: %d\n", status);
            
            // Read response
            char buf[4096];
            DWORD bytesRead = 0;
            while (WinHttpReadData(hRequest, buf, sizeof(buf), &bytesRead) && bytesRead > 0) {
                printf("Response (%d bytes): %.*s\n", bytesRead, bytesRead, buf);
                bytesRead = 0;
            }
        }
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    WSACleanup();
    printf("Done.\n");
    return 0;
}
