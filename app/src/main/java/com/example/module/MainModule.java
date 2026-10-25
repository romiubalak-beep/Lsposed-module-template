package com.example.module; // تأكد من تغيير هذا لاسم حزمتك

import android.util.Log;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Arrays;
import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

public class MainModule extends XposedModule {
    private static final String TAG = "CryptoHook";

    public MainModule() {
        super();
        // لا حاجة لاستدعاء أي شيء هنا
    }

    @Override
    public void onPackageLoaded(XposedModuleInterface.PackageLoadedParam param) {
        // التحقق من أن التطبيق المستهدف هو اللعبة
        if (!param.getPackageName().equals("jp.konami.pesam")) return;

        log(Log.INFO, TAG, "Module loaded for: " + param.getPackageName());
        
        // استدعاء دوال الاعتراض
        hookSecretKeySpec(param);
        hookIvParameterSpec(param);
        hookCipherDoFinal(param);
    }

    // دالة مساعدة للطباعة
    private void log(int priority, String tag, String msg) {
        Log.println(priority, tag, msg);
    }

    // دالة مساعدة لتحويل البايتات إلى Hex
    private String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // 1. اعتراض إنشاء المفتاح (SecretKeySpec)
    private void hookSecretKeySpec(XposedModuleInterface.PackageLoadedParam param) {
        try {
            Class<?> clazz = param.getClassLoader().loadClass("javax.crypto.spec.SecretKeySpec");
            Constructor<?> constructor = clazz.getConstructor(byte[].class, String.class);
            
            hook(constructor).intercept(chain -> {
                Object[] args = chain.getArgs().toArray();
                byte[] key = (byte[]) args[0];
                String algo = (String) args[1];
                log(Log.INFO, TAG, "[SecretKeySpec] Algo: " + algo + " Key: " + bytesToHex(key));
                return chain.proceed();
            });
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "Error hooking SecretKeySpec: " + t.getMessage());
        }
    }

    // 2. اعتراض إنشاء متجه التهيئة (IvParameterSpec)
    private void hookIvParameterSpec(XposedModuleInterface.PackageLoadedParam param) {
        try {
            Class<?> clazz = param.getClassLoader().loadClass("javax.crypto.spec.IvParameterSpec");
            Constructor<?> constructor = clazz.getConstructor(byte[].class);
            
            hook(constructor).intercept(chain -> {
                Object[] args = chain.getArgs().toArray();
                byte[] iv = (byte[]) args[0];
                log(Log.INFO, TAG, "[IvParameterSpec] IV: " + bytesToHex(iv));
                return chain.proceed();
            });
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "Error hooking IvParameterSpec: " + t.getMessage());
        }
    }

    // 3. اعتراض عملية التشفير/فك التشفير النهائية (Cipher.doFinal)
    private void hookCipherDoFinal(XposedModuleInterface.PackageLoadedParam param) {
        try {
            Class<?> clazz = param.getClassLoader().loadClass("javax.crypto.Cipher");
            Method method = clazz.getMethod("doFinal", byte[].class);
            
            hook(method).intercept(chain -> {
                Object[] args = chain.getArgs().toArray();
                byte[] input = (byte[]) args[0];
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
