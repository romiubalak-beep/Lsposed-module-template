package com.example.efootballhook; // تأكد من تغيير هذا إلى اسم الحزمة الخاص بك

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
    // 1. فلترة التطبيق المستهدف (لعبة eFootball)
    if (!lpparam.packageName.equals("jp.konami.pesam")) {
        return;
    }

    XposedBridge.log("CryptoHook: Loaded into eFootball!");

    try {
        // 2. اعتراض إنشاء المفتاح (SecretKeySpec)
        // هذا هو المكان الذي يتم فيه تمرير المفتاح (مثل CONFIGRULES_KEY)
        XposedHelpers.findAndHookConstructor(
                "javax.crypto.spec.SecretKeySpec",
                lpparam.classLoader,
                byte[].class, String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        byte[] keyBytes = (byte[]) param.args[0];
                        String algorithm = (String) param.args[1];
                        XposedBridge.log("=== SECRET KEY SPEC CREATED ===");
                        XposedBridge.log("Algorithm: " + algorithm);
                        XposedBridge.log("Key (Hex): " + bytesToHex(keyBytes));
                        XposedBridge.log("Key (String): " + new String(keyBytes));
                    }
                }
        );

        // 3. اعتراض متجه التهيئة (IV)
        XposedHelpers.findAndHookConstructor(
                "javax.crypto.spec.IvParameterSpec",
                lpparam.classLoader,
                byte[].class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        byte[] ivBytes = (byte[]) param.args[0];
                        XposedBridge.log("=== IV SPEC CREATED ===");
                        XposedBridge.log("IV (Hex): " + bytesToHex(ivBytes));
                    }
                }
        );

        // 4. اعتراض عملية التشفير/فك التشفير (Cipher.doFinal)
        XposedHelpers.findAndHookMethod(
                "javax.crypto.Cipher",
                lpparam.classLoader,
                "doFinal",
                byte[].class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        byte[] input = (byte[]) param.args[0];
                        XposedBridge.log("=== CIPHER DOFINAL CALLED ===");
                        XposedBridge.log("Input Data (Hex): " + bytesToHex(input));
                        // يمكنك محاولة طباعته كنص إذا كان قابلاً للقراءة
                        // XposedBridge.log("Input Data (String): " + new String(input));
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        byte[] result = (byte[]) param.getResult();
                        if (result != null) {
                            XposedBridge.log("Output Data (Hex): " + bytesToHex(result));
                        }
                    }
                }
        );

    } catch (Throwable t) {
        XposedBridge.log("CryptoHook Error: " + t.getMessage());
    }
}

// دالة مساعدة لتحويل البايتات إلى نص Hex
private static String bytesToHex(byte[] bytes) {
    if (bytes == null) return "null";
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
        sb.append(String.format("%02x", b));
    }
    return sb.toString();
}
