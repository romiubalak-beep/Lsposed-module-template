package com.yourname.efootballhook;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.util.Log;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

public class MainModule extends XposedModule {
    private static final String TAG = "NativeCryptoHook";
    private static final String TARGET_PACKAGE = "jp.konami.pesam";
    private static final String MODULE_PACKAGE = "com.yourname.efootballhook";

    public MainModule() {
        super();
    }

    @Override
    public void onPackageReady(XposedModuleInterface.PackageReadyParam param) {
        if (!param.getPackageName().equals(TARGET_PACKAGE)) return;

        Log.i(TAG, "Target package ready. Loading native library...");

        try {
            String soPath = resolveSoPath();
            if (soPath == null) {
                Log.e(TAG, "Could not resolve .so path");
                return;
            }

            Log.i(TAG, "Loading: " + soPath);
            System.load(soPath);
            Log.i(TAG, "Native library loaded successfully (JNI_OnLoad will start native_init)");

        } catch (Throwable t) {
            Log.e(TAG, "Failed to load native library: " + t.getMessage(), t);
        }
    }

    private String resolveSoPath() {
        // 1) المسار الثابت (الأسهل للاختبار)
        String hardcoded = "/data/local/tmp/libnative_hook.so";
        if (new java.io.File(hardcoded).exists()) {
            Log.i(TAG, "Using hardcoded path: " + hardcoded);
            return hardcoded;
        }

        // 2) عبر PackageManager (للاستخدام الدائم)
        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Object at = atClass.getMethod("currentActivityThread").invoke(null);
            android.content.Context ctx = (android.content.Context)
                    atClass.getMethod("getSystemContext").invoke(at);
            if (ctx != null) {
                ApplicationInfo ai = ctx.getPackageManager()
                        .getApplicationInfo(MODULE_PACKAGE,
                                PackageManager.MATCH_UNINSTALLED_PACKAGES
                                        | PackageManager.MATCH_DISABLED_COMPONENTS);
                if (ai != null && ai.sourceDir != null) {
                    Log.i(TAG, "Resolved via PackageManager: " + ai.sourceDir);
                    return extractSoFromApk(ai.sourceDir, ctx);
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "PackageManager method failed: " + t.getMessage());
        }

        return null;
    }

    private String extractSoFromApk(String apkPath, android.content.Context ctx) {
        try {
            java.util.zip.ZipFile zip = new java.util.zip.ZipFile(apkPath);
            java.util.zip.ZipEntry entry = zip.getEntry("lib/arm64-v8a/libnative_hook.so");
            if (entry == null) {
                Log.e(TAG, "libnative_hook.so not found in APK");
                zip.close();
                return null;
            }

            java.io.File cacheDir = ctx.getCacheDir();
            if (cacheDir == null) cacheDir = new java.io.File("/data/local/tmp");
            java.io.File outFile = new java.io.File(cacheDir, "libnative_hook_"
                    + System.currentTimeMillis() + ".so");

            java.io.InputStream is = zip.getInputStream(entry);
            java.io.FileOutputStream fos = new java.io.FileOutputStream(outFile);
            byte[] buf = new byte[8192];
            int len;
            while ((len = is.read(buf)) > 0) fos.write(buf, 0, len);
            is.close();
            fos.close();
            zip.close();

            outFile.setReadable(true, false);
            outFile.setExecutable(true, false);
            Log.i(TAG, "Extracted .so to: " + outFile.getAbsolutePath());
            return outFile.getAbsolutePath();
        } catch (Throwable t) {
            Log.e(TAG, "Extract failed: " + t.getMessage());
            return null;
        }
    }
}
