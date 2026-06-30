#pragma once
#ifdef _WIN32
#include <windows.h>

extern "C" void* peb_get_ntdll();
extern "C" void* find_ret_gadget(void* moduleBase);
extern "C" void* stack_spoof_call(void* target, void* gadget,
    void* arg1, void* arg2, void* arg3, void* arg4);

namespace anti {
namespace stack {

inline void* g_ret_gadget = nullptr;

inline void lazy_init_gadget() {
    if (g_ret_gadget) return;
    void* ntdll_base = peb_get_ntdll();
    if (ntdll_base) {
        g_ret_gadget = find_ret_gadget(ntdll_base);
    }
}

template <typename Ret, typename... Args>
inline Ret spoof_call(void* targetFunc, Args... args) {
    return ((Ret(WINAPI*)(Args...))targetFunc)(args...);
}

inline LSTATUS spoof_RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
    lazy_init_gadget();
    void* gadget = g_ret_gadget;
    if (!gadget) return RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    return (LSTATUS)(uintptr_t)stack_spoof_call((void*)RegOpenKeyExA, gadget,
        (void*)hKey, (void*)lpSubKey, (void*)(uintptr_t)ulOptions, (void*)(uintptr_t)samDesired);
}

inline HANDLE spoof_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    lazy_init_gadget();
    void* gadget = g_ret_gadget;
    if (!gadget) return CreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    return (HANDLE)stack_spoof_call((void*)CreateFileA, gadget,
        (void*)lpFileName, (void*)(uintptr_t)dwDesiredAccess, (void*)(uintptr_t)dwShareMode, (void*)lpSecurityAttributes);
}

inline BOOL spoof_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    lazy_init_gadget();
    void* gadget = g_ret_gadget;
    if (!gadget) return ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    return (BOOL)(uintptr_t)stack_spoof_call((void*)ReadFile, gadget,
        (void*)hFile, lpBuffer, (void*)(uintptr_t)nNumberOfBytesToRead, (void*)lpNumberOfBytesRead);
}

inline BOOL spoof_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    lazy_init_gadget();
    void* gadget = g_ret_gadget;
    if (!gadget) return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    return (BOOL)(uintptr_t)stack_spoof_call((void*)WriteFile, gadget,
        (void*)hFile, (void*)lpBuffer, (void*)(uintptr_t)nNumberOfBytesToWrite, (void*)lpNumberOfBytesWritten);
}

inline BOOL spoof_CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    lazy_init_gadget();
    void* gadget = g_ret_gadget;
    if (!gadget) return CreateProcessA(lpApplicationName, lpCommandLine,
        lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
        lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    return (BOOL)(uintptr_t)stack_spoof_call((void*)CreateProcessA, gadget,
        (void*)lpApplicationName, (void*)lpCommandLine, (void*)lpProcessAttributes, (void*)lpThreadAttributes);
}

} // namespace stack
} // namespace anti
#endif
