package com.byd.xposedhooks;

import android.util.Log;

import java.lang.reflect.Array;
import java.lang.reflect.Method;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

public final class CryptoToolHook {
    private static final String TAG = "BYD-Xposed";
    private static Method hookBridgeMethod;
    private static volatile boolean keysLogged;

    private CryptoToolHook() {
    }

    public static void install(ClassLoader classLoader) {
        String[] hookTargets = new String[]{
                "com.wbsk.CryptoTool",
                "jniutil.JniUtil",
                "com.bangcle.safekb.sec.SafeKBCrypter",
                "com.bangcle.comapiprotect.CheckCodeUtil"
        };
        for (String target : hookTargets) {
            hookClass(classLoader, target);
        }
    }

    private static void hookClass(ClassLoader loader,
                                  String className) {
        try {
            Class<?> clazz = loader.loadClass(className);
            Log.i(TAG, "Scanning " + className);
            for (Method method : clazz.getDeclaredMethods()) {
                hookMethod(className, method);
            }
        } catch (ClassNotFoundException e) {
            Log.i(TAG, className + " not present: " + e.getMessage());
        } catch (Throwable t) {
            Log.e(TAG, "Failed to hook " + className + " - " + Log.getStackTraceString(t));
        }
    }

    private static void hookMethod(String className, Method method) throws Throwable {
        final String tag = className + "#" + method.getName();
        final boolean maybeLogBangcleKeys =
                "com.bangcle.comapiprotect.CheckCodeUtil".equals(className)
                        && ("checkcode".equals(method.getName())
                        || "decheckcode".equals(method.getName()));
        method.setAccessible(true);
        hookMember(method, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                Log.i(TAG, tag + " args=" + formatArgs(param.args));
                if (maybeLogBangcleKeys) {
                    dumpBangcleStaticKeys(param.thisObject.getClass().getClassLoader());
                }
            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Log.i(TAG, tag + " -> " + formatValue(param.getResult()));
            }
        });
        Log.i(TAG, "Hooked " + tag);
    }

    private static String formatArgs(Object[] args) {
        if (args == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < args.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(formatValue(args[i]));
        }
        sb.append("]");
        return sb.toString();
    }

    private static void dumpBangcleStaticKeys(ClassLoader loader) {
        if (keysLogged) {
            return;
        }
        try {
            Class<?> settings = Class.forName("com.bangcle.safekb.api.BangcleKBSettings", false, loader);
            String rsa = (String) settings.getField("RSA_PUB_KEY").get(null);
            String sm2 = (String) settings.getField("SM2_PUB_KEY").get(null);
            String enc = (String) settings.getField("WBC_KEY_ENC").get(null);
            String dec = (String) settings.getField("WBC_KEY_DEC").get(null);
            String iv = (String) settings.getField("WBC_KEY_IV").get(null);
            Log.i(TAG, "Bangcle RSA_PUB_KEY len=" + (rsa != null ? rsa.length() : -1) + " val=" + rsa);
            Log.i(TAG, "Bangcle SM2_PUB_KEY len=" + (sm2 != null ? sm2.length() : -1) + " val=" + sm2);
            Log.i(TAG, "Bangcle WBC_KEY_ENC len=" + (enc != null ? enc.length() : -1) + " val=" + enc);
            Log.i(TAG, "Bangcle WBC_KEY_DEC len=" + (dec != null ? dec.length() : -1) + " val=" + dec);
            Log.i(TAG, "Bangcle WBC_KEY_IV len=" + (iv != null ? iv.length() : -1) + " val=" + iv);
            keysLogged = true;
        } catch (ClassNotFoundException e) {
            Log.i(TAG, "BangcleKBSettings not yet available: " + e.getMessage());
        } catch (Throwable t) {
            Log.e(TAG, "Failed dumping Bangcle keys - " + Log.getStackTraceString(t));
        }
    }

    private static String formatValue(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof byte[]) {
            byte[] data = (byte[]) value;
            return "len=" + data.length + " hex=" + toHex(data);
        }
        if (value instanceof CharSequence) {
            return value.toString();
        }
        if (value.getClass().isArray()) {
            int length = Array.getLength(value);
            StringBuilder sb = new StringBuilder();
            sb.append(value.getClass().getSimpleName())
                    .append("[")
                    .append(length)
                    .append("] [");
            for (int i = 0; i < length; i++) {
                if (i > 0) {
                    sb.append(", ");
                }
                sb.append(formatValue(Array.get(value, i)));
            }
            sb.append("]");
            return sb.toString();
        }
        return String.valueOf(value);
    }

    private static String toHex(byte[] data) {
        if (data == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static void hookMember(java.lang.reflect.Member member, XC_MethodHook callback) throws Throwable {
        Method bridge = hookBridgeMethod;
        if (bridge == null) {
            bridge = XposedBridge.class.getDeclaredMethod(
                    "hookMethod",
                    java.lang.reflect.Member.class,
                    XC_MethodHook.class
            );
            bridge.setAccessible(true);
            hookBridgeMethod = bridge;
        }
        bridge.invoke(null, member, callback);
    }
}
