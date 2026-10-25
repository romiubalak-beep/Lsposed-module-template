package com.yourname.efootballhook;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.util.Log;

import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

public class MainModule extends XposedModule {
    private static final String TAG = "NativeCryptoHook";
    private static final String TARGET_PACKAGE = "jp.konami.pesam";

    public MainModule() {
        super();
    }

    @Override
    public void onPackageReady(XposedModuleInterface.PackageReadyParam param) {
        if (!param.getPackageName().equals(TARGET_PACKAGE)) return;

        Log.i(TAG, "Module loaded. Attempting to load native library...");

        try {
            String soPath = buildSoPath();
            if (soPath == null) {
                Log.e(TAG, "Failed to resolve module APK path");
                return;
            }
            Log.i(TAG, "Loading native library from: " + soPath);
            System.load(soPath);
            Log.i(TAG, "Native library loaded successfully");
        } catch (Throwable t) {
            Log.e(TAG, "Failed to load native library: " + t.getMessage(), t);
        }
    }

    /**
     * إنشاء المسار المطلق لملف .so داخل APK الوحدة.
     * البنية عادة: /data/app/~~xxx/base.apk!/lib/arm64-v8a/libnative_hook.so
     */
    private String buildSoPath() {
        String apkPath = getModuleApkPath();
        if (apkPath == null) return null;

        // وفقًا للطريقة القياسية لتحميل .so المضمنة في APK، استخدم المحدد !/
        // ملاحظة: System.load يدعم هذا التنسيق لتحميل المكتبات الديناميكية مباشرة من داخل APK (على الأقل في بيئة ART)
        return apkPath + "!/lib/arm64-v8a/libnative_hook.so";
    }

    /**
     * محاولة الحصول على مسار APK للوحدة الحالية.
     * الأولوية: من Context -> من ActivityThread (بديل)
     */
    private String getModuleApkPath() {
        try {
            // المحاولة أولاً للحصول على Application من خلال ActivityThread
            // هذا هو Context العملية المستهدفة، sourceDir الخاص به هو مسار APK للعبة، وليس مسار الوحدة!
            // لذا لا يمكن استخدام Context العملية المستهدفة.
            // نحتاج إلى مسار APK الخاص بالوحدة، والذي يمكن الحصول عليه من خلال ApplicationInfo الخاص بالوحدة.
            // لكن في العملية المستهدفة، لا يمكننا الحصول مباشرة على ApplicationInfo الخاص بالوحدة.
            // الحل البديل: قراءة مسار التثبيت للوحدة من خلال PackageManager.
            // اسم حزمة الوحدة معروف: com.yourname.efootballhook
            Context ctx = getSystemContext();
            if (ctx != null) {
                ApplicationInfo ai = ctx.getPackageManager()
                        .getApplicationInfo("com.yourname.efootballhook", 0);
                if (ai != null && ai.sourceDir != null) {
                    Log.i(TAG, "Module APK path resolved: " + ai.sourceDir);
                    return ai.sourceDir;
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "Failed to get module APK path via PackageManager: " + t.getMessage());
        }

        // البديل: مسار APK الخاص بالوحدة مخزن مؤقتًا (غير مثالي، لكنه يعمل)
        // يمكنك تعيين مسار معروف يدويًا هنا للاختبار
        // return "/data/app/~~xxxx/com.yourname.efootballhook-xxxx/base.apk";
        return null;
    }

    private Context getSystemContext() {
        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Object at = atClass.getMethod("currentActivityThread").invoke(null);
            if (at == null) return null;
            return (Context) atClass.getMethod("getSystemContext").invoke(at);
        } catch (Throwable t) {
            return null;
        }
    }
}
