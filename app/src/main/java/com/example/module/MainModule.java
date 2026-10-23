package com.example.efootballkeylogger; // تأكد من تغيير هذا إلى اسم الحزمة الخاص بمشروعك

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class MainHook implements IXposedHookLoadPackage {

    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) throws Throwable {
        // 1. التحقق من أننا داخل لعبة eFootball فقط (jp.konami.pesam)
        if (!lpparam.packageName.equals("jp.konami.pesam")) {
            return;
        }

        XposedBridge.log("EfootballKeyLogger: Loaded into eFootball!");

        try {
            // 2. اعتراض دالة generateAESKey داخل كلاس GameActivity
            // الدالة تستقبل String وترجع SecretKey
            XposedHelpers.findAndHookMethod(
                    "com.epicgames.ue4.GameActivity", // اسم الكلاس
                    lpparam.classLoader,
                    "generateAESKey",                 // اسم الدالة
                    String.class,                     // نوع المعامل (String)
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            // هذا الكود ينفذ قبل الدالة الأصلية
                            String keyInput = (String) param.args[0];
                            
                            // 3. طباعة القيمة (كلمة المرور) في اللوج
                            XposedBridge.log("========================================");
                            XposedBridge.log("EfootballKeyLogger: Found CONFIGRULES_KEY Input!");
                            XposedBridge.log("VALUE: " + keyInput);
                            XposedBridge.log("========================================");
                        }

                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            // يمكننا هنا رؤية المفتاح الناتج (اختياري)
                            Object result = param.getResult();
                            if (result != null) {
                                XposedBridge.log("EfootballKeyLogger: Generated Key Object: " + result.toString());
                            }
                        }
                    }
            );
        } catch (Throwable t) {
            XposedBridge.log("EfootballKeyLogger Error: " + t.getMessage());
        }
    }
}
