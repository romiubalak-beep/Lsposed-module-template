package com.yourname.efootballhook;

import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModuleInterface;

public class MainModule extends XposedModule {

    @Override
    public void onPackageLoaded(XposedModuleInterface.PackageLoadedParam param) {
        // التحقق من اسم الحزمة
        if (!param.getPackageName().equals("jp.konami.pesam")) {
            return;
        }

        log("Efootball Hook: Loaded into eFootball!");

        try {
            // في API الحديث، نستخدم دالة hook() بدلاً من XposedHelpers
            // نحتاج إلى العثور على الكلاس أولاً
            Class<?> gameActivityClass = param.getClassLoader().loadClass("com.epicgames.ue4.GameActivity");
            
            // البحث عن الدالة generateAESKey
            for (java.lang.reflect.Method method : gameActivityClass.getDeclaredMethods()) {
                if (method.getName().equals("generateAESKey")) {
                    // اعتراض الدالة
                    hook(method).intercept(chain -> {
                        // طباعة المعامل الأول (String)
                        String keyInput = (String) chain.getArgs().get(0);
                        log("========================================");
                        log("Efootball Hook: Found Key Input!");
                        log("VALUE: " + keyInput);
                        log("========================================");
                        
                        // استمرار تنفيذ الدالة الأصلية
                        return chain.proceed();
                    });
                    break;
                }
            }
        } catch (Throwable t) {
            log("Efootball Hook Error: " + t.getMessage());
        }
    }
}
