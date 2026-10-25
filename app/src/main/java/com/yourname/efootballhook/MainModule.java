package com.yourname.efootballhook;

import android.util.Log;

import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

public class MainModule extends XposedModule {
    private static final String TAG = "NativeCryptoHook";
    private static final String TARGET_PACKAGE = "jp.konami.pesam";
    private static String moduleApkPath = null;

    public MainModule() {
        super();
    }

    @Override
    public void onModuleLoaded(XposedModuleInterface.ModuleLoadedParam param) {
        super.onModuleLoaded(param);
        // محاولة الحصول على مسار APK الخاص بالوحدة النمطية من خلال انعكاس ModuleLoadedParam
        // إذا لم يكن موجوداً، سنستخدم البديل أدناه
        try {
            java.lang.reflect.Method m = param.getClass().getMethod("getModulePath");
            moduleApkPath = (String) m.invoke(param);
            Log.i(TAG, "Module APK path captured: " + moduleApkPath);
        } catch (Throwable t) {
            Log.w(TAG, "getModulePath() not available via reflection: " + t.getMessage());
        }
    }

    @Override
    public void onPackageReady(XposedModuleInterface.PackageReadyParam param) {
        if (!param.getPackageName().equals(TARGET_PACKAGE)) return;

        if (moduleApkPath == null) {
            Log.e(TAG, "Module APK path not captured, cannot load native library");
            return;
        }

        String soPath = moduleApkPath + "!/lib/arm64-v8a/libnative_hook.so";
        Log.i(TAG, "Loading native library from: " + soPath);
        try {
            System.load(soPath);
            Log.i(TAG, "Native library loaded successfully");
        } catch (Throwable t) {
            Log.e(TAG, "Failed to load native library: " + t.getMessage(), t);
        }
    }
}
