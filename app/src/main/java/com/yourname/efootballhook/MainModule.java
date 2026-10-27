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

        Log.i(TAG, "Target package ready. Installing hooks...");

        ClassLoader gameClassLoader = getGameClassLoader(param);
        if (gameClassLoader == null) {
            Log.e(TAG, "❌ Could not get game ClassLoader");
            return;
        }
        Log.i(TAG, "Game ClassLoader: " + gameClassLoader);

        // 1. اعتراضات للكشف عن CONFIGRULES_KEY
        hookClassGetDeclaredField();
        hookFieldGet(gameClassLoader);

        // 2. اعتراضات على GameActivity
        hookGenerateAESKey(gameClassLoader);
        hookGetConfigRulesDecompressed(gameClassLoader);
    }

    private ClassLoader getGameClassLoader(XposedModuleInterface.PackageReadyParam param) {
        try {
            Method m = param.getClass().getMethod("getClassLoader");
            Object cl = m.invoke(param);
            if (cl instanceof ClassLoader) return (ClassLoader) cl;
        } catch (Throwable ignored) {}
        try {
            Class<?> atClass = Class.forName("android.app.ActivityThread");
            Object app = atClass.getMethod("currentApplication").invoke(null);
            if (app != null) {
                Method getCL = app.getClass().getMethod("getClassLoader");
                Object cl = getCL.invoke(app);
                if (cl instanceof ClassLoader) return (ClassLoader) cl;
            }
        } catch (Throwable ignored) {}
        return null;
    }

    private void hookClassGetDeclaredField() {
        try {
            Class<?> classClass = Class.forName("java.lang.Class");
            Method target = classClass.getDeclaredMethod("getDeclaredField", String.class);
            target.setAccessible(true);

            XposedInterface.Hooker hooker = new XposedInterface.Hooker() {
                @Override
                public Object intercept(XposedInterface.Chain chain) throws Throwable {
                    Object thisClass = chain.getThisObject();
                    Object arg = chain.getArg(0);
                    String fieldName = (arg instanceof String) ? (String) arg : null;

                    if ("CONFIGRULES_KEY".equals(fieldName)) {
                        Log.i(TAG, "==================================================");
                        Log.i(TAG, "[!!!] Class.getDeclaredField(CONFIGRULES_KEY)");
                        Log.i(TAG, "  called on class: " + thisClass);
                        try {
                            Object result = chain.proceed();
                            Log.i(TAG, "  RESULT: " + result);
                            Log.i(TAG, "==================================================");
                            return result;
                        } catch (Throwable t) {
                            Log.e(TAG, "  THREW: " + t.getClass().getName() + ": " + t.getMessage());
                            Log.i(TAG, "==================================================");
                            throw t;
                        }
                    }
                    return chain.proceed();
                }
            };

            hook(target).intercept(hooker);
            Log.i(TAG, "✅ Hooked Class.getDeclaredField");
        } catch (Throwable t) {
            Log.e(TAG, "❌ hookClassGetDeclaredField failed: " + t.getMessage(), t);
        }
    }

    private void hookFieldGet(ClassLoader gameCL) {
        try {
            Class<?> fieldClass = Class.forName("java.lang.reflect.Field");
            Method target = fieldClass.getDeclaredMethod("get", Object.class);
            target.setAccessible(true);

            XposedInterface.Hooker hooker = new XposedInterface.Hooker() {
                @Override
                public Object intercept(XposedInterface.Chain chain) throws Throwable {
                    Object thisField = chain.getThisObject();
                    if (!(thisField instanceof Field)) return chain.proceed();
                    
                    Field f = (Field) thisField;
                    String name = f.getName();
                    String declaringClass = f.getDeclaringClass().getName();

                    Object result = chain.proceed();

                    if (name.equals("CONFIGRULES_KEY")) {
                        Log.i(TAG, "==================================================");
                        Log.i(TAG, "[!!!] Field.get(CONFIGRULES_KEY) CALLED!");
                        Log.i(TAG, "  declaring class: " + declaringClass);
                        Log.i(TAG, "  type: " + f.getType().getName());
                        Log.i(TAG, "  VALUE: " + result);
                        if (result instanceof String) {
                            String s = (String) result;
                            Log.i(TAG, "  length: " + s.length());
                            StringBuilder hex = new StringBuilder();
                            for (char c : s.toCharArray()) {
                                hex.append(String.format("%02x", (int) c));
                            }
                            Log.i(TAG, "  hex: " + hex.toString());
                        }
                        Log.i(TAG, "==================================================");
                    }
                    return result;
                }
            };

            hook(target).intercept(hooker);
            Log.i(TAG, "✅ Hooked Field.get");
        } catch (Throwable t) {
            Log.e(TAG, "❌ hookFieldGet failed: " + t.getMessage(), t);
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
