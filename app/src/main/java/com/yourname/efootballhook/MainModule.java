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
        Log.i(TAG, "Target package ready, native library should be loaded by Vector");
        // لم يعد بحاجة إلى System.load، Vector قام بالفعل بتحميل libnative_hook.so وفقًا لـ native_init.list
    }
}
