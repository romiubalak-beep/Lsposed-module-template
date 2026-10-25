package com.yourname.efootballhook;

import android.util.Log;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;
import java.lang.reflect.Method;
import java.util.Arrays;

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

            // البحث عن دالة nativeSetConfigRulesVariables
            for (Method method : gameActivityClass.getDeclaredMethods()) {
                if (method.getName().equals("nativeSetConfigRulesVariables")) {
                    
                    log(Log.INFO, "EfootballHook", "Found nativeSetConfigRulesVariables, hooking...");

                    // اعتراض الدالة
                    hook(method).intercept(chain -> {
                        // المعامل الأول (index 0) هو String[] strArr
                        Object[] args = chain.getArgs().toArray();
                        if (args.length > 0 && args[0] instanceof String[]) {
                            String[] strArr = (String[]) args[0];
                            
                            log(Log.INFO, "EfootballHook", "========================================");
                            log(Log.INFO, "EfootballHook", "nativeSetConfigRulesVariables called!");
                            
                            // طباعة المصفوفة كاملة
                            for (int i = 0; i < strArr.length; i += 2) {
                                if (i + 1 < strArr.length) {
                                    String key = strArr[i];
                                    String value = strArr[i + 1];
                                    
                                    // طباعة كل زوج
                                    log(Log.INFO, "EfootballHook", "KEY: " + key + " | VALUE: " + value);
                                    
                                    // تمييز CONFIGRULES_KEY إذا وجد
                                    if ("CONFIGRULES_KEY".equals(key)) {
                                        log(Log.ERROR, "EfootballHook", ">>> FOUND CONFIGRULES_KEY: " + value + " <<<");
                                    }
                                }
                            }
                            log(Log.INFO, "EfootballHook", "========================================");
                        }
                        
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
