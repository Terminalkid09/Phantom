#pragma once
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>
#include <vector>

namespace smb {

inline std::vector<std::string> pending_smb_commands;

struct SmbPipeServer {
    std::string name;
    std::atomic<bool> running{false};
    std::thread thread;
    HANDLE pipeHandle = INVALID_HANDLE_VALUE;

    void start() {
        if (name.empty()) {
            char buf[64];
            DWORD pid = GetCurrentProcessId();
            snprintf(buf, sizeof(buf), "\\\\.\\pipe\\phantom-svc-%lu-%lu", pid, GetTickCount());
            name = buf;
        }
        running = true;
        thread = std::thread([this]() { run(); });
    }

    void stop() {
        running = false;
        if (pipeHandle != INVALID_HANDLE_VALUE) {
            DisconnectNamedPipe(pipeHandle);
            CloseHandle(pipeHandle);
            pipeHandle = INVALID_HANDLE_VALUE;
        }
        // join before destruction so the thread never touches freed memory
        if (thread.joinable()) {
            thread.join();
        }
    }

    std::string pipe_path() const { return name; }

    bool send_response(const std::string& data) {
        if (pipeHandle == INVALID_HANDLE_VALUE) return false;
        DWORD written = 0;
        DWORD len = static_cast<DWORD>(data.size());
        if (!WriteFile(pipeHandle, &len, sizeof(len), &written, nullptr)) return false;
        if (written != sizeof(len)) return false;
        if (len == 0) return true;
        if (!WriteFile(pipeHandle, data.c_str(), len, &written, nullptr)) return false;
        return written == len;
    }

    std::string read_command() {
        if (pipeHandle == INVALID_HANDLE_VALUE) return "";
        DWORD len = 0, read = 0;
        if (!ReadFile(pipeHandle, &len, sizeof(len), &read, nullptr)) return "";
        if (read != sizeof(len) || len == 0 || len > 65536) return "";
        std::string data(len, '\0');
        if (!ReadFile(pipeHandle, &data[0], len, &read, nullptr)) return "";
        if (read != len) return "";
        return data;
    }

    std::string wait_for_client() {
        if (pipeHandle != INVALID_HANDLE_VALUE) {
            DisconnectNamedPipe(pipeHandle);
            CloseHandle(pipeHandle);
        }
        pipeHandle = CreateNamedPipeA(
            name.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            8192, 8192, 0, nullptr
        );
        if (pipeHandle == INVALID_HANDLE_VALUE) return "SMB pipe create failed.";
        if (!ConnectNamedPipe(pipeHandle, nullptr)) {
            if (GetLastError() != ERROR_PIPE_CONNECTED) {
                return "SMB pipe connect failed.";
            }
        }
        return "";
    }

private:
    void run() {
        while (running) {
            std::string err = wait_for_client();
            if (!err.empty()) {
                Sleep(1000);
                continue;
            }
            while (running) {
                std::string cmd = read_command();
                if (cmd.empty()) break;
                pending_smb_commands.push_back(cmd);
            }
        }
    }
};

inline SmbPipeServer* active_pipe = nullptr;

inline std::string start_smb_pipe(const std::string& name) {
    if (active_pipe) return "SMB pipe already running on " + active_pipe->pipe_path();
    auto* p = new SmbPipeServer();
    if (!name.empty()) p->name = "\\\\.\\pipe\\" + name;
    p->start();
    active_pipe = p;
    return "SMB pipe started on " + p->pipe_path();
}

inline std::string stop_smb_pipe() {
    if (!active_pipe) return "No active SMB pipe.";
    active_pipe->stop();
    delete active_pipe;
    active_pipe = nullptr;
    pending_smb_commands.clear();
    return "SMB pipe stopped.";
}

// Pop the next command received over the named pipe ("" when empty).
// The main loop drains this queue every cycle.
inline std::string pop_pending_command() {
    if (pending_smb_commands.empty()) return "";
    std::string cmd = pending_smb_commands.front();
    pending_smb_commands.erase(pending_smb_commands.begin());
    return cmd;
}

inline std::string process_smb_command(const std::string& cmd) {
    return cmd;
}

}  // namespace smb
#endif
