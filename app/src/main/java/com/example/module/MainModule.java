import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class MainModule implements IXposedHookLoadPackage {
    private static final String TAG = "CryptoHook";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        // استهدف التطبيق المحدد فقط لتجنب إبطاء النظام
        if (!lpparam.packageName.equals("jp.konami.pesam")) return;
        
        XposedBridge.log(TAG + " Module loaded for: " + lpparam.packageName);
        hookCrypto(lpparam);
    }

    private void hookCrypto(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            // 1. اعتراض إنشاء المفتاح (SecretKeySpec)
            XposedHelpers.findAndHookConstructor(
                "javax.crypto.spec.SecretKeySpec", 
                lpparam.classLoader,
                byte[].class, String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        byte[] key = (byte[]) param.args[0];
                        String algo = (String) param.args[1];
                        XposedBridge.log(TAG + " [SecretKeySpec] Algo: " + algo + " Key: " + bytesToHex(key));
                    }
                }
            );

            // 2. اعتراض إنشاء متجه التهيئة (IvParameterSpec)
            XposedHelpers.findAndHookConstructor(
                "javax.crypto.spec.IvParameterSpec",
                lpparam.classLoader,
                byte[].class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        byte[] iv = (byte[]) param.args[0];
                        XposedBridge.log(TAG + " [IvParameterSpec] IV: " + bytesToHex(iv));
                    }
                }
            );

            // 3. اعتراض عملية التشفير/فك التشفير النهائية (Cipher.doFinal)
            XposedHelpers.findAndHookMethod(
                "javax.crypto.Cipher", 
                lpparam.classLoader, 
                "doFinal", 
                byte[].class, 
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        byte[] input = (byte[]) param.args[0];
                        XposedBridge.log(TAG + " [Cipher.doFinal] Input: " + bytesToHex(input));
                    }
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        byte[] result = (byte[]) param.getResult();
                        XposedBridge.log(TAG + " [Cipher.doFinal] Result: " + bytesToHex(result));
                    }
                }
            );

        } catch (Throwable t) {
            XposedBridge.log(TAG + " Error setting hooks: " + t.getMessage());
        }
    }

    // دالة مساعدة لتحويل البايتات إلى نص سداسي عشري (Hex) مقروء
    private String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
