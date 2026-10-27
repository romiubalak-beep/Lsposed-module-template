package com.yourname.efootballhook;

import android.util.Log;
import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

import java.lang.reflect.Field;
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

        Log.i(TAG, "Target package ready. Installing Java hooks...");

        hookGenerateAESKey();
        hookGetConfigRulesDecompressed();
        inspectConfigRulesKeyField();
    }

    private void hookGenerateAESKey() {
        try {
            Class<?> gameActivity = Class.forName("com.epicgames.ue4.GameActivity");
            Method target = gameActivity.getDeclaredMethod("generateAESKey", String.class);
            target.setAccessible(true);

            XposedInterface.Hooker hooker = new XposedInterface.Hooker() {
                @Override
                public Object intercept(XposedInterface.Chain chain) throws Throwable {
                    Object arg = chain.getArg(0);
                    String password = (arg instanceof String) ? (String) arg : null;

                    Log.i(TAG, "==================================================");
                    Log.i(TAG, "[!!!] GameActivity.generateAESKey CALLED");
                    Log.i(TAG, "  CONFIGRULES_KEY = " + password);
                    if (password != null) {
                        Log.i(TAG, "  length = " + password.length());
                        StringBuilder sb = new StringBuilder();
                        for (char c : password.toCharArray()) {
                            sb.append(String.format("%02x", (int) c));
                        }
                        Log.i(TAG, "  hex = " + sb.toString());
                    }
                    Log.i(TAG, "==================================================");

                    return chain.proceed();
                }
            };

            // ✅ التصحيح: hook(Executable).intercept(Hooker)
            hook(target).intercept(hooker);
            Log.i(TAG, "✅ Hooked GameActivity.generateAESKey");
        } catch (Throwable t) {
            Log.e(TAG, "❌ hookGenerateAESKey failed: " + t.getMessage(), t);
        }
    }

    private void hookGetConfigRulesDecompressed() {
        try {
            Class<?> gameActivity = Class.forName("com.epicgames.ue4.GameActivity");
            Method target = gameActivity.getDeclaredMethod("getConfigRulesDecompressed", byte[].class);
            target.setAccessible(true);

            XposedInterface.Hooker hooker = new XposedInterface.Hooker() {
                @Override
                public Object intercept(XposedInterface.Chain chain) throws Throwable {
                    Object arg = chain.getArg(0);
                    if (arg instanceof byte[]) {
                        byte[] data = (byte[]) arg;
                        Log.i(TAG, "==================================================");
                        Log.i(TAG, "[!!!] getConfigRulesDecompressed CALLED");
                        Log.i(TAG, "  data length: " + data.length);
                        if (data.length >= 10) {
                            int n = Math.min(64, data.length);
                            StringBuilder sb = new StringBuilder();
                            for (int i = 0; i < n; i++) {
                                sb.append(String.format("%02x", data[i]));
                            }
                            Log.i(TAG, "  data[0.." + n + "]: " + sb.toString());
                        }
                        Log.i(TAG, "==================================================");
                    }
                    return chain.proceed();
                }
            };

            // ✅ التصحيح
            hook(target).intercept(hooker);
            Log.i(TAG, "✅ Hooked GameActivity.getConfigRulesDecompressed");
        } catch (Throwable t) {
            Log.e(TAG, "❌ hookGetConfigRulesDecompressed failed: " + t.getMessage(), t);
        }
    }

    private void inspectConfigRulesKeyField() {
        try {
            Class<?> gameActivity = Class.forName("com.epicgames.ue4.GameActivity");
            Field[] fields = gameActivity.getDeclaredFields();
            for (Field f : fields) {
                if (f.getName().equals("CONFIGRULES_KEY")) {
                    f.setAccessible(true);
                    Log.i(TAG, "==================================================");
                    Log.i(TAG, "Found field: " + f.getName());
                    Log.i(TAG, "  type: " + f.getType().getName());
                    Log.i(TAG, "  modifiers: " + java.lang.reflect.Modifier.toString(f.getModifiers()));

                    if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) {
                        try {
                            Object value = f.get(null);
                            Log.i(TAG, "  STATIC VALUE: " + value);
                            if (value instanceof String) {
                                String str = (String) value;
                                Log.i(TAG, "  length: " + str.length());
                                StringBuilder sb = new StringBuilder();
                                for (char c : str.toCharArray()) {
                                    sb.append(String.format("%02x", (int) c));
                                }
                                Log.i(TAG, "  hex: " + sb.toString());
                            }
                        } catch (Throwable t) {
                            Log.e(TAG, "  static get failed: " + t.getMessage());
                        }
                    }
                    Log.i(TAG, "==================================================");
                }
            }
        } catch (Throwable t) {
            Log.e(TAG, "inspectConfigRulesKeyField failed: " + t.getMessage(), t);
        }
    }
}
