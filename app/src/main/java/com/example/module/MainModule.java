package com.example.module;

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

        Log.i(TAG, "Module loaded. Loading native library...");
        try {
            // تحميل المكتبة الأصلية التي تحتوي على native_init
            System.loadLibrary("native_hook");
        } catch (Throwable t) {
            Log.e(TAG, "Failed to load native library: " + t.getMessage());
        }
    }
}
