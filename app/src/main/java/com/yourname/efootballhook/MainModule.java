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

        // احصل على ClassLoader الخاص باللعبة (وليس الوحدة النمطية)
        ClassLoader gameClassLoader = getGameClassLoader(param);
        if (gameClassLoader == null) {
            Log.e(TAG, "❌ Could not get game ClassLoader");
            return;
        }
        Log.i(TAG, "Game ClassLoader: " + gameClassLoader);

        hookGenerateAESKey(gameClassLoader);
        hookGetConfigRulesDecompressed(gameClassLoader);
        inspectConfigRulesKeyField(gameClassLoader);
    }

    /**
     * احصل على ClassLoader اللعبة.
     * param.getClassLoader() يعطي ClassLoader اللعبة (وليس الوحدة).
     */
    private ClassLoader getGameClassLoader(XposedModuleInterface.PackageReadyParam param) {
        try {
            // الطريقة 1: من param
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
            // الطريقة 2: ActivityThread.currentApplication()
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

    private void inspectConfigRulesKeyField(ClassLoader gameCL) {
        try {
            Class<?> gameActivity = Class.forName("com.epicgames.ue4.GameActivity", false, gameCL);
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
