package com.example.module; // تأكد من تطابق اسم الحزمة

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

        // اعتراض التشفير وفك التشفير
        hookCipher(param);
        // اعتراض دوال التجزئة (Hash)
        hookMessageDigest(param);
        // اعتراض دوال التحقق من الرسائل (MAC)
        hookMac(param);
        // اعتراض المفاتيح
        hookSecretKeySpec(param);
    }

    private String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // 1. اعتراض Cipher (تشفير/فك تشفير)
    private void hookCipher(XposedModuleInterface.PackageReadyParam param) {
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
        } catch (Throwable t) { log(Log.ERROR, TAG, "Cipher hook error: " + t.getMessage()); }
    }

    // 2. اعتراض MessageDigest (مثل SHA-256)
    private void hookMessageDigest(XposedModuleInterface.PackageReadyParam param) {
        try {
            Class<?> clazz = param.getClassLoader().loadClass("java.security.MessageDigest");
            Method method = clazz.getMethod("digest", byte[].class);
            hook(method).intercept(chain -> {
                byte[] input = (byte[]) chain.getArgs().get(0);
                log(Log.INFO, TAG, "[MessageDigest.digest] Input: " + bytesToHex(input));
                Object result = chain.proceed();
                if (result instanceof byte[]) {
                    log(Log.INFO, TAG, "[MessageDigest.digest] Hash: " + bytesToHex((byte[]) result));
                }
                return result;
            });
        } catch (Throwable t) { log(Log.ERROR, TAG, "MessageDigest hook error: " + t.getMessage()); }
    }

    // 3. اعتراض Mac (التحقق من الرسائل)
    private void hookMac(XposedModuleInterface.PackageReadyParam param) {
        try {
            Class<?> clazz = param.getClassLoader().loadClass("javax.crypto.Mac");
            Method method = clazz.getMethod("doFinal", byte[].class);
            hook(method).intercept(chain -> {
                byte[] input = (byte[]) chain.getArgs().get(0);
                log(Log.INFO, TAG, "[Mac.doFinal] Input: " + bytesToHex(input));
                Object result = chain.proceed();
                if (result instanceof byte[]) {
                    log(Log.INFO, TAG, "[Mac.doFinal] Result: " + bytesToHex((byte[]) result));
                }
                return result;
            });
        } catch (Throwable t) { log(Log.ERROR, TAG, "Mac hook error: " + t.getMessage()); }
    }

    // 4. اعتراض SecretKeySpec (المفاتيح)
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
        } catch (Throwable t) { log(Log.ERROR, TAG, "SecretKeySpec hook error: " + t.getMessage()); }
    }
}
