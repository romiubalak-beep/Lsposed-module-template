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

    /**
     * استخراج .so من APK الوحدة إلى cacheDir الخاص باللعبة.
     * cacheDir يسمح بتعيين executable، بخلاف /data/local/tmp/.
     */
    private String resolveSoPath() {
        try {
            // 1) احصل على Context للنظام
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Object at = atClass.getMethod("currentActivityThread").invoke(null);
            android.content.Context ctx = (android.content.Context)
                    atClass.getMethod("getSystemContext").invoke(at);
            if (ctx == null) {
                Log.e(TAG, "System context is null");
                return null;
            }

            // 2) احصل على مسار APK الوحدة
            String apkPath = null;
            try {
                ApplicationInfo ai = ctx.getPackageManager()
                        .getApplicationInfo(MODULE_PACKAGE,
                                PackageManager.MATCH_UNINSTALLED_PACKAGES
                                        | PackageManager.MATCH_DISABLED_COMPONENTS);
                if (ai != null && ai.sourceDir != null) {
                    apkPath = ai.sourceDir;
                }
            } catch (Throwable t) {
                Log.w(TAG, "PackageManager failed: " + t.getMessage());
            }

            // 3) fallback: ابحث في /data/app
            if (apkPath == null) {
                java.io.File appDir = new java.io.File("/data/app");
                java.io.File[] dirs = appDir.listFiles();
                if (dirs != null) {
                    for (java.io.File d : dirs) {
                        if (d.getName().contains(MODULE_PACKAGE)) {
                            java.io.File[] files = d.listFiles();
                            if (files != null) {
                                for (java.io.File f : files) {
                                    if (f.getName().equals("base.apk")) {
                                        apkPath = f.getAbsolutePath();
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (apkPath == null) {
                Log.e(TAG, "Could not find module APK");
                return null;
            }
            Log.i(TAG, "Module APK: " + apkPath);

            // 4) استخرج .so إلى cacheDir الخاص بالعملية الحالية (اللعبة)
            //    ⚠️ getCacheDir() من ctx (system context) يعطي cache للنظام،
            //    لذا نستخدم مسار cache اللعبة مباشرة:
            //    /data/user/0/jp.konami.pesam/cache/
            java.io.File cacheDir = new java.io.File(
                    "/data/user/0/" + TARGET_PACKAGE + "/cache");
            if (!cacheDir.exists()) {
                // fallback: استخدم ctx.getCacheDir() (قد يكون cache النظام)
                cacheDir = ctx.getCacheDir();
            }
            if (cacheDir == null || !cacheDir.canWrite()) {
                Log.e(TAG, "Cache dir not writable: " + cacheDir);
                return null;
            }
            Log.i(TAG, "Using cache dir: " + cacheDir.getAbsolutePath());

            // 5) اسم فريد لتجنب التخزين المؤقت
            java.io.File outFile = new java.io.File(cacheDir,
                    "libnative_hook_" + System.currentTimeMillis() + ".so");

            // 6) استخرج .so من APK
            java.util.zip.ZipFile zip = new java.util.zip.ZipFile(apkPath);
            java.util.zip.ZipEntry entry = zip.getEntry("lib/arm64-v8a/libnative_hook.so");
            if (entry == null) {
                Log.e(TAG, "libnative_hook.so not found in APK");
                zip.close();
                return null;
            }

            java.io.InputStream is = zip.getInputStream(entry);
            java.io.FileOutputStream fos = new java.io.FileOutputStream(outFile);
            byte[] buf = new byte[8192];
            int len;
            while ((len = is.read(buf)) > 0) fos.write(buf, 0, len);
            is.close();
            fos.close();
            zip.close();

            // 7) اضبط الصلاحيات
            outFile.setReadable(true, false);
            outFile.setExecutable(true, false);
            Log.i(TAG, "Extracted to: " + outFile.getAbsolutePath());
            return outFile.getAbsolutePath();

        } catch (Throwable t) {
            Log.e(TAG, "Auto-extract failed: " + t.getMessage(), t);
            return null;
        }
    }
}
