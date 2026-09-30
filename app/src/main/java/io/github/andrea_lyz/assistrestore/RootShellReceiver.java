package io.github.andrea_lyz.assistrestore;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.TimeUnit;

/**
 * Executes configured shell targets from the module APK's UID.
 *
 * <p>The Xposed hook runs inside SystemUI. Calling {@code su} there would grant superuser rights to
 * SystemUI itself, so the hook instead sends an explicit authenticated broadcast here. The random
 * nonce is generated in the module app's private preferences and mirrored to libxposed
 * RemotePreferences for the injected side.</p>
 */
public final class RootShellReceiver extends BroadcastReceiver {
    private static final String TAG = "AssistRestore.RootShell";

    public static final String MODULE_PACKAGE = "io.github.andrea_lyz.assistrestore";
    public static final String ACTION_EXECUTE_ROOT_SHELL =
            MODULE_PACKAGE + ".action.EXECUTE_ROOT_SHELL";
    public static final String EXTRA_COMMAND = "command";
    public static final String EXTRA_TOKEN = "token";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || !ACTION_EXECUTE_ROOT_SHELL.equals(intent.getAction())) {
            return;
        }

        SharedPreferences prefs =
                context.getSharedPreferences(AssistConfig.PREFS, Context.MODE_PRIVATE);
        String expected = prefs.getString(AssistConfig.KEY_SHELL_TOKEN, "");
        String supplied = intent.getStringExtra(EXTRA_TOKEN);
        if (!sameToken(expected, supplied)) {
            Log.w(TAG, "Rejected unauthenticated root-shell request");
            return;
        }

        String command = normalizeCommand(intent.getStringExtra(EXTRA_COMMAND));
        if (command.isEmpty()) {
            Log.w(TAG, "Ignored empty root-shell command");
            return;
        }

        PendingResult pending = goAsync();
        Thread worker = new Thread(() -> {
            try {
                Process process = new ProcessBuilder("su", "-c", command)
                        .redirectErrorStream(true)
                        .start();
                drainAsync(process);
                Log.i(TAG, "Started root-shell command (length=" + command.length() + ")");
            } catch (Throwable t) {
                Log.e(TAG, "Failed to start root-shell command", t);
            } finally {
                pending.finish();
            }
        }, "assistrestore-root-shell");
        worker.start();
    }

    /**
     * Triggers the superuser manager from the module app's own UID and verifies that uid 0 is
     * actually available. Intended for the settings screen's "request/check root" button.
     */
    public static boolean requestRoot() {
        Process process = null;
        try {
            process = new ProcessBuilder("su", "-c", "id").redirectErrorStream(true).start();
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            try (InputStream input = process.getInputStream()) {
                byte[] buffer = new byte[1024];
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    output.write(buffer, 0, read);
                }
            }
            if (!process.waitFor(20, TimeUnit.SECONDS)) {
                process.destroy();
                return false;
            }
            String text = output.toString(StandardCharsets.UTF_8.name());
            return process.exitValue() == 0 && text.contains("uid=0");
        } catch (Throwable t) {
            return false;
        } finally {
            if (process != null) {
                try {
                    process.getInputStream().close();
                } catch (Throwable ignored) {
                }
                try {
                    process.getErrorStream().close();
                } catch (Throwable ignored) {
                }
                try {
                    process.getOutputStream().close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    /**
     * Android root managers expose {@code su}, not desktop {@code sudo}. Accept a leading
     * {@code sudo} as a convenience alias so commands copied from the UI can still be pasted
     * verbatim.
     */
    private static String normalizeCommand(String raw) {
        if (raw == null) {
            return "";
        }
        String command = raw.trim();
        if ("sudo".equals(command)) {
            return "";
        }
        if (command.length() > 4
                && command.startsWith("sudo")
                && Character.isWhitespace(command.charAt(4))) {
            command = command.substring(5).trim();
        }
        return command;
    }

    private static boolean sameToken(String expected, String supplied) {
        if (expected == null || expected.isEmpty() || supplied == null || supplied.isEmpty()) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                supplied.getBytes(StandardCharsets.UTF_8));
    }

    /** Drain command output so verbose shell commands cannot block on a full pipe. */
    private static void drainAsync(Process process) {
        Thread drain = new Thread(() -> {
            try (InputStream input = process.getInputStream()) {
                byte[] buffer = new byte[4096];
                while (input.read(buffer) >= 0) {
                    // Intentionally discard command output; never leak arbitrary shell output to logcat.
                }
            } catch (Throwable ignored) {
            }
        }, "assistrestore-root-shell-drain");
        drain.start();
    }
}
