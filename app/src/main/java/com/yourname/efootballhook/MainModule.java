package com.yourname.efootballhook;

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

        Log.i(TAG, "Target package ready. Loading native library...");

        try {
            String soPath = "/data/user/0/" + TARGET_PACKAGE + "/cache/libnative_hook.so";
            if (!new java.io.File(soPath).exists()) {
                Log.e(TAG, "File not found: " + soPath);
                return;
            }
            Log.i(TAG, "Loading: " + soPath);
            System.load(soPath);
            Log.i(TAG, "Native library loaded successfully");
        } catch (Throwable t) {
            Log.e(TAG, "Failed: " + t.getMessage(), t);
        }
    }
}
