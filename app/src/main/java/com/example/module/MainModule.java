package com.example.module; // تأكد من تغيير هذا لاسم حزمتك

import android.util.Log;
import java.lang.reflect.Constructor;
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

        hookSecretKeySpec(param);
        hookIvParameterSpec(param);
        hookCipherDoFinal(param);
    }

    private String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // 1. اعتراض إنشاء المفتاح
    private void hookSecretKeySpec(XposedModuleInterface.PackageReadyParam param) {
        try {
            Class<?> clazz = param.getClassLoader().loadClass("javax.crypto.spec.SecretKeySpec");
            Constructor<?> constructor = clazz.getConstructor(byte[].class, String.class);

            hook(constructor).intercept(chain -> {
                byte[] key = (byte[]) chain.getArgs().get(0);
                String algo = (String) chain.getArgs().get(1);
                log(Log.INFO, TAG, "[SecretKeySpec] Algo: " + algo + " Key: " + bytesToHex(key));
                return chain.proceed();
            });
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "Error hooking SecretKeySpec: " + t.getMessage());
        }
    }

    // 2. اعتراض متجه التهيئة
    private void hookIvParameterSpec(XposedModuleInterface.PackageReadyParam param) {
        try {
            Class<?> clazz = param.getClassLoader().loadClass("javax.crypto.spec.IvParameterSpec");
            Constructor<?> constructor = clazz.getConstructor(byte[].class);

            hook(constructor).intercept(chain -> {
                byte[] iv = (byte[]) chain.getArgs().get(0);
                log(Log.INFO, TAG, "[IvParameterSpec] IV: " + bytesToHex(iv));
                return chain.proceed();
            });
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "Error hooking IvParameterSpec: " + t.getMessage());
        }
    }

    // 3. اعتراض التشفير/فك التشفير
    private void hookCipherDoFinal(XposedModuleInterface.PackageReadyParam param) {
        try {
            Class<?> clazz = param.getClassLoader().loadClass("javax.crypto.Cipher");
            Method method = clazz.getMethod("doFinal", byte[].class);

            hook(method).intercept(chain -> {
                byte[] input = (byte[]) chain.getArgs().get(0);
                log(Log.INFO, TAG, "[Cipher.doFinal] Input: " + bytesToHex(input));

                Object result = chain.proceed();

                if (result instanceof byte[]) {
                    log(Log.INFO, TAG, "[Cipher.doFinal] Result: " + bytesToHex((byte[]) result));
                }
                return result;
            });
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "Error hooking Cipher.doFinal: " + t.getMessage());
        }
    }
}
