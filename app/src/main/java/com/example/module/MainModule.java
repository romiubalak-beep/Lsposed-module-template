package com.example.module;

import android.util.Log;
import java.lang.reflect.Method;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

public class MainModule extends XposedModule {
    private static final String TAG = "CryptoHook";
    private static final String TARGET_PACKAGE = "jp.konami.pesam";

    public MainModule() {
        super();
    }

    @Override
    public void onPackageReady(XposedModuleInterface.PackageReadyParam param) {
        if (!param.getPackageName().equals(TARGET_PACKAGE)) return;

        log(Log.INFO, TAG, "Module loaded for: " + param.getPackageName());

        try {
            // اعتراض دالة generateAESKey في GameActivity
            Class<?> gameActivity = param.getClassLoader().loadClass("com.epicgames.ue4.GameActivity");
            Method method = gameActivity.getDeclaredMethod("generateAESKey", String.class);
            method.setAccessible(true);

            hook(method).intercept(chain -> {
                String password = (String) chain.getArgs().get(0);
                log(Log.INFO, TAG, "[generateAESKey] Password: " + password);
                Object result = chain.proceed();
                return result;
            });
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "Error hooking generateAESKey: " + t.getMessage());
        }
    }
}
