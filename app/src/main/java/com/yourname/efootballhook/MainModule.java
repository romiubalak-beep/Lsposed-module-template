package com.yourname.efootballhook;

import android.util.Log;
import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

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

        ClassLoader gameClassLoader = getGameClassLoader(param);
        if (gameClassLoader == null) {
            Log.e(TAG, "❌ Could not get game ClassLoader");
            return;
        }
        Log.i(TAG, "Game ClassLoader: " + gameClassLoader);

        // 1. اطبع كل الحقول أولاً
        inspectAllFields(gameClassLoader);

        // 2. ثبّت الـ hooks
        hookGenerateAESKey(gameClassLoader);
        hookGetConfigRulesDecompressed(gameClassLoader);
    }

    private ClassLoader getGameClassLoader(XposedModuleInterface.PackageReadyParam param) {
        try {
            Method m = param.getClass().getMethod("getClassLoader");
            Object cl = m.invoke(param);
            if (cl instanceof ClassLoader) {
                Log.i(TAG, "ClassLoader from param.getClassLoader()");
                return (ClassLoader) cl;
            }
        } catch (Throwable t) {
            Log.w(TAG, "param.getClassLoader() failed: " + t.getMessage());
        }

        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Object app = atClass.getMethod("currentApplication").invoke(null);
            if (app != null) {
                Method getCL = app.getClass().getMethod("getClassLoader");
                Object cl = getCL.invoke(app);
                if (cl instanceof ClassLoader) {
                    Log.i(TAG, "ClassLoader from ActivityThread.currentApplication()");
                    return (ClassLoader) cl;
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "ActivityThread method failed: " + t.getMessage());
        }

        return null;
    }

    /**
     * اطبع كل حقول GameActivity، مع قيم الحقول static.
     */
    private void inspectAllFields(ClassLoader gameCL) {
        try {
            Class<?> gameActivity = Class.forName("com.epicgames.ue4.GameActivity", false, gameCL);
            Field[] fields = gameActivity.getDeclaredFields();
            Log.i(TAG, "==================================================");
            Log.i(TAG, "=== GameActivity has " + fields.length + " declared fields ===");
            Log.i(TAG, "==================================================");

            for (Field f : fields) {
                String mods = Modifier.toString(f.getModifiers());
                String type = f.getType().getName();
                String name = f.getName();

                // اطبع السطر الأساسي
                StringBuilder line = new StringBuilder();
                line.append("  [").append(mods).append("] ");
                line.append(type).append(" ").append(name);

                // إذا كان static، اقرأ القيمة
                if (Modifier.isStatic(f.getModifiers())) {
                    try {
                        f.setAccessible(true);
                        Object value = f.get(null);
                        line.append(" = ");
                        if (value == null) {
                            line.append("null");
                        } else if (value instanceof String) {
                            String s = (String) value;
                            line.append("\"").append(s).append("\"");
                            line.append(" (length=").append(s.length()).append(", hex=");
                            for (char c : s.toCharArray()) {
                                line.append(String.format("%02x", (int) c));
                            }
                            line.append(")");
                        } else if (value instanceof byte[]) {
                            byte[] bytes = (byte[]) value;
                            line.append("byte[").append(bytes.length).append("] {");
                            int n = Math.min(32, bytes.length);
                            for (int i = 0; i < n; i++) {
                                line.append(String.format("%02x", bytes[i]));
                            }
                            if (bytes.length > 32) line.append("...");
                            line.append("}");
                        } else if (value instanceof int[]) {
                            int[] arr = (int[]) value;
                            line.append("int[").append(arr.length).append("] {");
                            int n = Math.min(16, arr.length);
                            for (int i = 0; i < n; i++) {
                                line.append(arr[i]);
                                if (i < n - 1) line.append(", ");
                            }
                            if (arr.length > 16) line.append("...");
                            line.append("}");
                        } else {
                            String v = value.toString();
                            if (v.length() > 200) v = v.substring(0, 200) + "...";
                            line.append(v);
                        }
                    } catch (Throwable t) {
                        line.append(" (get failed: ").append(t.getMessage()).append(")");
                    }
                }

                Log.i(TAG, line.toString());

                // إذا كان CONFIGRULES_KEY، اطبع تفاصيل إضافية
                if (name.equals("CONFIGRULES_KEY")) {
                    Log.i(TAG, "  ┌─────────────────────────────────────");
                    Log.i(TAG, "  │ 🎯 CONFIGRULES_KEY FOUND");
                    Log.i(TAG, "  │ type: " + type);
                    Log.i(TAG, "  │ modifiers: " + mods);
                    Log.i(TAG, "  │ isStatic: " + Modifier.isStatic(f.getModifiers()));
                    if (Modifier.isStatic(f.getModifiers())) {
                        try {
                            f.setAccessible(true);
                            Object value = f.get(null);
                            if (value instanceof String) {
                                String s = (String) value;
                                Log.i(TAG, "  │ VALUE: " + s);
                                Log.i(TAG, "  │ length: " + s.length());
                                StringBuilder hex = new StringBuilder();
                                for (char c : s.toCharArray()) {
                                    hex.append(String.format("%02x", (int) c));
                                }
                                Log.i(TAG, "  │ hex: " + hex.toString());
                            } else {
                                Log.i(TAG, "  │ VALUE: " + value);
                            }
                        } catch (Throwable t) {
                            Log.e(TAG, "  │ static get failed: " + t.getMessage());
                        }
                    }
                    Log.i(TAG, "  └─────────────────────────────────────");
                }
            }

            Log.i(TAG, "==================================================");
            Log.i(TAG, "=== End of GameActivity fields ===");
            Log.i(TAG, "==================================================");

        } catch (Throwable t) {
            Log.e(TAG, "inspectAllFields failed: " + t.getMessage(), t);
        }
    }

    private void hookGenerateAESKey(ClassLoader gameCL) {
        try {
            Class<?> gameActivity = Class.forName("com.epicgames.ue4.GameActivity", false, gameCL);
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

            hook(target).intercept(hooker);
            Log.i(TAG, "✅ Hooked GameActivity.generateAESKey");
        } catch (Throwable t) {
            Log.e(TAG, "❌ hookGenerateAESKey failed: " + t.getMessage(), t);
        }
    }

    private void hookGetConfigRulesDecompressed(ClassLoader gameCL) {
        try {
            Class<?> gameActivity = Class.forName("com.epicgames.ue4.GameActivity", false, gameCL);
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

            hook(target).intercept(hooker);
            Log.i(TAG, "✅ Hooked GameActivity.getConfigRulesDecompressed");
        } catch (Throwable t) {
            Log.e(TAG, "❌ hookGetConfigRulesDecompressed failed: " + t.getMessage(), t);
        }
    }
}
