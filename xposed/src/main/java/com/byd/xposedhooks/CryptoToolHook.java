package com.byd.xposedhooks;

import android.util.Base64;
import android.util.Log;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

public final class CryptoToolHook {
    private static final String TAG = "BYD-Xposed";
    private static Method hookBridgeMethod;
    private static volatile boolean settingsLogged;
    private static final Set<String> HOOKED_CLASSES = Collections.synchronizedSet(new HashSet<>());
    private static final Set<String> PENDING_CLASSES = Collections.synchronizedSet(new HashSet<>());
    private static final Set<String> OBSERVED_LOADS = Collections.synchronizedSet(new HashSet<>());
    private static final ConcurrentHashMap<Object, CipherContext> CIPHER_CONTEXT = new ConcurrentHashMap<>();
    private static volatile boolean loadHookInstalled;
    private static volatile boolean cipherHookInstalled;

    private CryptoToolHook() {
    }

    public static void install(ClassLoader classLoader) {
        final String[] hookTargets = new String[]{
                "com.wbsk.CryptoTool",
                "jniutil.JniUtil",
                "com.bangcle.safekb.sec.SafeKBCrypter",
                "com.bangcle.comapiprotect.CheckCodeUtil"
        };
        for (String target : hookTargets) {
            hookClass(classLoader, target);
        }
        hookCipherMethods();
        ensureLoadClassHook();
    }

    private static void hookClass(ClassLoader loader,
                                  String className) {
        try {
            Class<?> clazz = loader.loadClass(className);
            hookClass(clazz);
        } catch (ClassNotFoundException e) {
            PENDING_CLASSES.add(className);
            Log.i(TAG, className + " not present yet – deferring hook");
        } catch (Throwable t) {
            Log.e(TAG, "Failed to hook " + className + " - " + Log.getStackTraceString(t));
        }
    }

    private static void hookClass(Class<?> clazz) throws Throwable {
        if (clazz == null) {
            return;
        }
        final String className = clazz.getName();
        if (HOOKED_CLASSES.contains(className)) {
            return;
        }
        Log.i(TAG, "Scanning " + className);
        for (Method method : clazz.getDeclaredMethods()) {
            hookMethod(className, method);
        }
        HOOKED_CLASSES.add(className);
        PENDING_CLASSES.remove(className);
    }

    private static void hookMethod(String className, Method method) throws Throwable {
        final String tag = className + "#" + method.getName();
        final boolean maybeLogBangcleSettings =
                "com.bangcle.comapiprotect.CheckCodeUtil".equals(className)
                        && ("checkcode".equals(method.getName())
                        || "decheckcode".equals(method.getName()));
        method.setAccessible(true);
        hookMember(method, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                Log.i(TAG, tag + " args=" + formatArgs(param.args));
                if (maybeLogBangcleSettings) {
                    dumpBangcleStaticSettings(param.thisObject.getClass().getClassLoader());
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

    private static void dumpBangcleStaticSettings(ClassLoader loader) {
        if (settingsLogged) {
            return;
        }
        try {
            Class<?> settings = Class.forName("com.bangcle.safekb.api.BangcleKBSettings", false, loader);
            for (Field field : settings.getDeclaredFields()) {
                if (!Modifier.isStatic(field.getModifiers())) {
                    continue;
                }
                field.setAccessible(true);
                Object value = field.get(null);
                Log.i(TAG, "Bangcle " + field.getName()
                        + " type=" + field.getType().getSimpleName()
                        + " value=" + describeBangcleValue(value));
            }
            settingsLogged = true;
        } catch (ClassNotFoundException e) {
            Log.i(TAG, "BangcleKBSettings not yet available: " + e.getMessage());
        } catch (Throwable t) {
            Log.e(TAG, "Failed dumping Bangcle settings - " + Log.getStackTraceString(t));
        }
    }

    private static String describeBangcleValue(Object value) {
        if (value instanceof CharSequence) {
            CharSequence text = (CharSequence) value;
            return "len=" + text.length() + " val=" + text;
        }
        return formatValue(value);
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

    private static void hookCipherMethods() {
        if (cipherHookInstalled) {
            return;
        }
        synchronized (CryptoToolHook.class) {
            if (cipherHookInstalled) {
                return;
            }
            try {
                Class<?> cipherClass = javax.crypto.Cipher.class;
                for (Method method : cipherClass.getDeclaredMethods()) {
                    String name = method.getName();
                    if ("init".equals(name)) {
                        hookMember(method, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) {
                                Object cipher = param.thisObject;
                                if (cipher == null) {
                                    return;
                                }
                                try {
                                    javax.crypto.Cipher c = (javax.crypto.Cipher) cipher;
                                    CipherContext ctx = new CipherContext();
                                    ctx.algorithm = safeAlgorithm(c);
                                    ctx.mode = argsToMode(param.args);
                                    ctx.keyHex = extractKeyHex(param.args);
                                    ctx.ivHex = extractIvHex(c);
                                    CIPHER_CONTEXT.put(cipher, ctx);
                                    if (ctx.algorithm.contains("AES") || ctx.algorithm.contains("SM4")) {
                                        Log.i(TAG, "Cipher.init algo=" + ctx.algorithm + " mode=" + modeName(ctx.mode)
                                                + " key=" + ctx.keyHex + (ctx.ivHex != null ? " iv=" + ctx.ivHex : ""));
                                    }
                                } catch (Throwable t) {
                                    Log.e(TAG, "Cipher.init hook failure - " + Log.getStackTraceString(t));
                                }
                            }
                        });
                    } else if ("doFinal".equals(name)) {
                        hookMember(method, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) {
                                captureInput(param);
                            }

                            @Override
                            protected void afterHookedMethod(MethodHookParam param) {
                                logCipherResult(param);
                            }
                        });
                    }
                }
                cipherHookInstalled = true;
            } catch (Throwable t) {
                Log.e(TAG, "Failed to hook javax.crypto.Cipher - " + Log.getStackTraceString(t));
            }
        }
    }

    private static void captureInput(XC_MethodHook.MethodHookParam param) {
        Object cipher = param.thisObject;
        CipherContext ctx = CIPHER_CONTEXT.get(cipher);
        if (ctx == null) {
            return;
        }
        if (!ctx.algorithm.contains("AES") && !ctx.algorithm.contains("SM4")) {
            return;
        }
        try {
            byte[] input = extractBytes(param.args);
            if (input != null) {
                ctx.lastInput = input.clone();
            }
        } catch (Throwable t) {
            // ignore
        }
    }

    private static void logCipherResult(XC_MethodHook.MethodHookParam param) {
        Object cipher = param.thisObject;
        CipherContext ctx = CIPHER_CONTEXT.get(cipher);
        if (ctx == null) {
            return;
        }
        if (!ctx.algorithm.contains("AES") && !ctx.algorithm.contains("SM4")) {
            return;
        }
        try {
            byte[] output = extractResultBytes(param.getResult());
            if (output == null) {
                return;
            }
            String baseLabel = "Cipher.doFinal algo=" + ctx.algorithm + " mode=" + modeName(ctx.mode);
            if (ctx.keyHex != null) {
                baseLabel += " key=" + ctx.keyHex;
            }
            if (ctx.ivHex != null) {
                baseLabel += " iv=" + ctx.ivHex;
            }
            if (ctx.lastInput != null) {
                baseLabel += " inputBase64=" + Base64.encodeToString(ctx.lastInput, Base64.NO_WRAP);
            }
            baseLabel += " outputBase64=" + Base64.encodeToString(output, Base64.NO_WRAP);
            Log.i(TAG, baseLabel);
        } catch (Throwable t) {
            Log.e(TAG, "Cipher.doFinal hook failure - " + Log.getStackTraceString(t));
        } finally {
            ctx.lastInput = null;
        }
    }

    private static String safeAlgorithm(javax.crypto.Cipher cipher) {
        try {
            return cipher.getAlgorithm();
        } catch (Throwable t) {
            return "unknown";
        }
    }

    private static int argsToMode(Object[] args) {
        if (args == null || args.length == 0) {
            return -1;
        }
        if (args[0] instanceof Integer) {
            return (Integer) args[0];
        }
        return -1;
    }

    private static String extractKeyHex(Object[] args) {
        if (args == null) {
            return null;
        }
        for (Object arg : args) {
            if (arg instanceof javax.crypto.SecretKey) {
                try {
                    byte[] encoded = ((javax.crypto.SecretKey) arg).getEncoded();
                    if (encoded != null) {
                        return toHex(encoded);
                    }
                } catch (Throwable ignore) {
                    // ignore
                }
            }
        }
        return null;
    }

    private static String extractIvHex(javax.crypto.Cipher cipher) {
        try {
            byte[] iv = cipher.getIV();
            if (iv != null) {
                return toHex(iv);
            }
        } catch (Throwable ignore) {
            // ignore
        }
        return null;
    }

    private static String modeName(int mode) {
        switch (mode) {
            case javax.crypto.Cipher.ENCRYPT_MODE:
                return "ENCRYPT";
            case javax.crypto.Cipher.DECRYPT_MODE:
                return "DECRYPT";
            case javax.crypto.Cipher.WRAP_MODE:
                return "WRAP";
            case javax.crypto.Cipher.UNWRAP_MODE:
                return "UNWRAP";
            default:
                return "UNKNOWN(" + mode + ")";
        }
    }

    private static byte[] extractBytes(Object[] args) {
        if (args == null) {
            return null;
        }
        for (Object arg : args) {
            if (arg instanceof byte[]) {
                return (byte[]) arg;
            }
        }
        return null;
    }

    private static byte[] extractResultBytes(Object result) {
        if (result instanceof byte[]) {
            return (byte[]) result;
        }
        return null;
    }

    private static void ensureLoadClassHook() {
        if (loadHookInstalled) {
            return;
        }
        synchronized (CryptoToolHook.class) {
            if (loadHookInstalled) {
                return;
            }
            try {
                Method bridge = XposedBridge.class.getDeclaredMethod(
                        "hookMethod",
                        java.lang.reflect.Member.class,
                        XC_MethodHook.class
                );
                bridge.setAccessible(true);
                final Method loadClass = ClassLoader.class.getDeclaredMethod("loadClass", String.class);
                loadClass.setAccessible(true);
            bridge.invoke(null, loadClass, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Object result = param.getResult();
                    if (!(result instanceof Class)) {
                        return;
                        }
                        String requestedName = (String) param.args[0];
                        if (requestedName != null) {
                            if (!OBSERVED_LOADS.contains(requestedName)) {
                                OBSERVED_LOADS.add(requestedName);
                                Log.i(TAG, "ClassLoader.loadClass -> " + requestedName);
                            }
                        }
                        if (requestedName == null || !PENDING_CLASSES.contains(requestedName)) {
                            return;
                        }
                        try {
                            hookClass((Class<?>) result);
                        } catch (Throwable t) {
                            Log.e(TAG, "Deferred hook failed for " + requestedName + " - " + Log.getStackTraceString(t));
                        }
                    }
                });
                loadHookInstalled = true;
                Log.i(TAG, "Installed ClassLoader#loadClass(String) hook for deferred targets");
            } catch (Throwable t) {
                Log.e(TAG, "Failed to install loadClass hook - " + Log.getStackTraceString(t));
            }
        }
    }

    private static final class CipherContext {
        String algorithm;
        int mode;
        String keyHex;
        String ivHex;
        byte[] lastInput;
    }
}
