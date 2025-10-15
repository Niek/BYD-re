package com.byd.xposedhooks;

import android.util.Log;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

public final class CryptoToolHook {

    private static final String TAG = "BYD-Xposed";

    private CryptoToolHook() {
    }

    public static void install(ClassLoader classLoader) {
        hookMethod("laesEncryptStringWithBase64", classLoader, "Encrypt");
        hookMethod("laesDecryptStringWithBase64", classLoader, "Decrypt");
    }

    private static void hookMethod(String methodName, ClassLoader classLoader, String tagSuffix) {
        try {
            Class<?> cryptoToolClass = classLoader.loadClass("com.wbsk.CryptoTool");
            java.lang.reflect.Method targetMethod = cryptoToolClass.getDeclaredMethod(
                    methodName,
                    String.class,
                    String.class,
                    byte[].class
            );
            targetMethod.setAccessible(true);

            XC_MethodHook callback = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String payload = (String) param.args[0];
                    String key = (String) param.args[1];
                    Log.i(TAG, tagSuffix + "-in payload=" + payload);
                    Log.i(TAG, tagSuffix + "-in key=" + key);
                }

                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Object result = param.getResult();
                    Log.i(TAG, tagSuffix + "-out result=" + result);
                }
            };

            java.lang.reflect.Method hookMethod = XposedBridge.class.getDeclaredMethod(
                    "hookMethod",
                    java.lang.reflect.Member.class,
                    XC_MethodHook.class
            );
            hookMethod.setAccessible(true);
            hookMethod.invoke(null, targetMethod, callback);

            XposedBridge.log(TAG + ": Hooked " + methodName);
        } catch (ClassNotFoundException cnfe) {
            XposedBridge.log(TAG + ": CryptoTool class not found: " + cnfe.getMessage());
        } catch (Throwable t) {
            XposedBridge.log(TAG + ": Failed to hook " + methodName + " - " + Log.getStackTraceString(t));
        }
    }
}
