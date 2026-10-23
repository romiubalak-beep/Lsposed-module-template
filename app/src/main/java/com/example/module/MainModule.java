package com.yourname.efootballhook; // تأكد من تغيير هذا لاسم الحزمة الخاص بك

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainModule implements IXposedHookLoadPackage {

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        // التحقق من أننا داخل اللعبة المستهدفة
        if (!lpparam.packageName.equals("jp.konami.pesam")) {
            return;
        }

        XposedBridge.log("Efootball Hook: Loaded into eFootball!");

        try {
            // اعتراض دالة generateAESKey في كلاس GameActivity
            XposedHelpers.findAndHookMethod(
                    "com.epicgames.ue4.GameActivity", // اسم الكلاس (بدون .java)
                    lpparam.classLoader,              // يجب تمرير ClassLoader الخاص بالتطبيق
                    "generateAESKey",                 // اسم الدالة
                    String.class,                     // نوع المعامل الوحيد (String)
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            // هذا الكود ينفذ قبل الدالة الأصلية
                            String keyInput = (String) param.args[0];
                            
                            // طباعة القيمة في سجل LSPosed
                            XposedBridge.log("========================================");
                            XposedBridge.log("Efootball Hook: Found Key Input!");
                            XposedBridge.log("VALUE: " + keyInput);
                            XposedBridge.log("========================================");
                        }
                    }
            );
        } catch (Throwable t) {
            XposedBridge.log("Efootball Hook Error: " + t.getMessage());
        }
    }
}
