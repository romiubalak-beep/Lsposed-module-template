package com.yourname.efootballhook;

import android.util.Log;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;
import java.lang.reflect.Method;
import java.security.Key;

public class MainModule extends XposedModule {

    @Override
    public void onPackageReady(XposedModuleInterface.PackageReadyParam param) {
        if (!param.getPackageName().equals("jp.konami.pesam")) {
            return;
        }

        log(Log.INFO, "EfootballHook", "Loaded into eFootball!");

        try {
            ClassLoader classLoader = param.getClassLoader();
            Class<?> gameActivityClass = classLoader.loadClass("com.epicgames.ue4.GameActivity");

            // البحث عن دالة generateAESKey التي تستقبل String
            for (Method method : gameActivityClass.getDeclaredMethods()) {
                if (method.getName().equals("generateAESKey")) {
                    log(Log.INFO, "EfootballHook", "Found method: " + method.toString());

                    // اعتراض الدالة
                    hook(method).intercept(chain -> {
                        // 1. طباعة المعاملات (Input)
                        String inputStr = (String) chain.getArgs().get(0);
                        log(Log.INFO, "EfootballHook", ">>> Calling generateAESKey with Input: " + inputStr);

                        // 2. تنفيذ الدالة الأصلية والحصول على النتيجة
                        Object result = chain.proceed();

                        // 3. طباعة النتيجة (Output)
                        if (result instanceof Key) {
                            Key key = (Key) result;
                            log(Log.INFO, "EfootballHook", "<<< generateAESKey returned Key Algorithm: " + key.getAlgorithm());
                            log(Log.INFO, "EfootballHook", "<<< generateAESKey returned Key Format: " + key.getFormat());
                            
                            // تحويل المفتاح إلى Hex لقراءته
                            byte[] encoded = key.getEncoded();
                            if (encoded != null) {
                                StringBuilder hexString = new StringBuilder();
                                for (byte b : encoded) {
                                    String hex = Integer.toHexString(0xff & b);
                                    if (hex.length() == 1) hexString.append('0');
                                    hexString.append(hex);
                                }
                                log(Log.INFO, "EfootballHook", "<<< generateAESKey returned Key Hex: " + hexString.toString());
                            }
                        } else {
                            log(Log.INFO, "EfootballHook", "<<< generateAESKey returned: " + result);
                        }

                        return result;
                    });
                    break; // وجدنا الدالة، لا داعي للبحث أكثر
                }
            }
        } catch (Throwable t) {
            log(Log.ERROR, "EfootballHook", "Hook Error: " + t.getMessage());
        }
    }
}
