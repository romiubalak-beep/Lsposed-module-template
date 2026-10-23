package com.yourname.efootballhook;

import android.util.Log;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModuleInterface;

public class MainModule extends XposedModule {

    @Override
    public void onPackageReady(XposedModuleInterface.PackageReadyParam param) {
        // التحقق من اسم الحزمة
        if (!param.getPackageName().equals("jp.konami.pesam")) {
            return;
        }

        // في API 101، دالة التسجيل تحتاج إلى (priority, tag, message)
        log(Log.INFO, "EfootballHook", "Loaded into eFootball!");

        try {
            // جلب ClassLoader الخاص بالتطبيق (متوفر في onPackageReady)
            ClassLoader classLoader = param.getClassLoader();
            Class<?> gameActivityClass = classLoader.loadClass("com.epicgames.ue4.GameActivity");
            
            // البحث عن دالة generateAESKey
            for (java.lang.reflect.Method method : gameActivityClass.getDeclaredMethods()) {
                if (method.getName().equals("generateAESKey")) {
                    // اعتراض الدالة باستخدام interceptor-chain الجديد
                    hook(method).intercept(chain -> {
                        // طباعة المعامل الأول (String)
                        String keyInput = (String) chain.getArgs().get(0);
                        log(Log.INFO, "EfootballHook", "========================================");
                        log(Log.INFO, "EfootballHook", "Found Key Input!");
                        log(Log.INFO, "EfootballHook", "VALUE: " + keyInput);
                        log(Log.INFO, "EfootballHook", "========================================");
                        
                        // استمرار تنفيذ الدالة الأصلية
                        return chain.proceed();
                    });
                    break;
                }
            }
        } catch (Throwable t) {
            log(Log.ERROR, "EfootballHook", "Hook Error: " + t.getMessage());
        }
    }
}
