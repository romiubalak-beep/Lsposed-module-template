package com.yourname.efootballhook;

import android.util.Log;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

import java.lang.reflect.Method;

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

        // 1. تحميل المكتبة الأصلية (ShadowHook للتشفير)
        try {
            String soPath = "/data/user/0/" + TARGET_PACKAGE + "/cache/libnative_hook.so";
            if (new java.io.File(soPath).exists()) {
                Log.i(TAG, "Loading native: " + soPath);
                System.load(soPath);
                Log.i(TAG, "Native loaded successfully");
            }
        } catch (Throwable t) {
            Log.e(TAG, "Failed to load native: " + t.getMessage(), t);
        }

        // 2. Java Hooks للكشف عن CONFIGRULES_KEY
        try {
            Class<?> gameActivity = Class.forName("com.epicgames.ue4.GameActivity");

            // 2.1. Hook generateAESKey(String) — الأهم
            try {
                Method m = gameActivity.getDeclaredMethod("generateAESKey", String.class);
                m.setAccessible(true);
                hook(m, new XposedInterface.Hooker() {
                    @Override
                    public Object intercept(XposedInterface.Chain chain) throws Throwable {
                        String password = (String) chain.getArg(0);
                        Log.i(TAG, "==================================================");
                        Log.i(TAG, "[generateAESKey] CALLED!");
                        Log.i(TAG, "  CONFIGRULES_KEY = " + password);
                        if (password != null) {
                            Log.i(TAG, "  length = " + password.length());
                            StringBuilder sb = new StringBuilder();
                            for (char c : password.toCharArray()) {
                                sb.append(String.format("%02x", (int) c));
                            }
                            Log.i(TAG, "  bytes = " + sb.toString());
                        }
                        Log.i(TAG, "==================================================");
                        return chain.proceed();
                    }
                });
                Log.i(TAG, "✅ Hooked generateAESKey");
            } catch (Throwable t) {
                Log.e(TAG, "❌ hook generateAESKey: " + t.getMessage(), t);
            }

            // 2.2. Hook getConfigRulesDecompressed(byte[]) — للتحقق
            try {
                Method m = gameActivity.getDeclaredMethod("getConfigRulesDecompressed", byte[].class);
                m.setAccessible(true);
                hook(m, new XposedInterface.Hooker() {
                    @Override
                    public Object intercept(XposedInterface.Chain chain) throws Throwable {
                        byte[] input = (byte[]) chain.getArg(0);
                        if (input != null && input.length > 0) {
                            Log.i(TAG, "==================================================");
                            Log.i(TAG, "[getConfigRulesDecompressed] CALLED!");
                            Log.i(TAG, "  input length = " + input.length);
                            if (input.length >= 10) {
                                Log.i(TAG, "  magic = 0x" + 
                                    String.format("%02x%02x", input[0], input[1]));
                                // اطبع أول 32 بايت
                                StringBuilder sb = new StringBuilder();
                                for (int i = 0; i < Math.min(input.length, 32); i++) {
                                    sb.append(String.format("%02x", input[i]));
                                }
                                Log.i(TAG, "  first 32 bytes = " + sb.toString());
                            }
                            Log.i(TAG, "==================================================");
                        }
                        return chain.proceed();
                    }
                });
                Log.i(TAG, "✅ Hooked getConfigRulesDecompressed");
            } catch (Throwable t) {
                Log.e(TAG, "❌ hook getConfigRulesDecompressed: " + t.getMessage(), t);
            }

        } catch (Throwable t) {
            Log.e(TAG, "❌ Java hook failed: " + t.getMessage(), t);
        }
    }
}
