package com.byd.xposedhooks;

import android.app.Application;
import android.os.Build;
import android.provider.Settings;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

public final class CryptoToolHook {
    private static final String TAG = "BYD-Xposed";
    private static final int LOGCAT_CHUNK_LIMIT = 3900;
    private static final long HTTP_BODY_CAPTURE_LIMIT = 128L * 1024L;

    private static final String CLASS_CRYPTO_TOOL = "com.wbsk.CryptoTool";
    private static final String CLASS_JNI_UTIL = "jniutil.JniUtil";
    private static final String CLASS_CHECK_CODE = "com.bangcle.comapiprotect.CheckCodeUtil";
    private static final String HOOK_ALL_METHODS = "*";

    private static final Map<String, String[]> ACTIVE_HOOKS;

    static {
        Map<String, String[]> hooks = new LinkedHashMap<>();
        hooks.put(CLASS_CRYPTO_TOOL, new String[]{
                HOOK_ALL_METHODS
        });
        hooks.put(CLASS_JNI_UTIL, new String[]{
                HOOK_ALL_METHODS
        });
        hooks.put(CLASS_CHECK_CODE, new String[]{
                HOOK_ALL_METHODS
        });
        ACTIVE_HOOKS = Collections.unmodifiableMap(hooks);
    }

    private static Method hookBridgeMethod;
    private static volatile boolean installed;
    private static volatile boolean settingsLogged;
    private static volatile boolean environmentLogged;
    private static volatile boolean nativeDumped;
    private static volatile boolean cipherHookInstalled;
    private static volatile boolean okHttpHookInstalled;
    private static volatile boolean mqttHookInstalled;

    private static final ConcurrentHashMap<Object, CipherContext> CIPHER_CONTEXT = new ConcurrentHashMap<>();
    private static final ThreadLocal<Boolean> BANGCLE_SELF_DECODE = new ThreadLocal<>();
    private static final AtomicInteger LOG_SEQUENCE = new AtomicInteger();

    private CryptoToolHook() {
    }

    public static void install(ClassLoader classLoader) {
        if (installed) {
            return;
        }
        synchronized (CryptoToolHook.class) {
            if (installed) {
                return;
            }
            for (Map.Entry<String, String[]> entry : ACTIVE_HOOKS.entrySet()) {
                hookClassMethods(classLoader, entry.getKey(), entry.getValue());
            }
            hookCipherMethods();
            hookOkHttp(classLoader);
            hookMqtt(classLoader);
            installed = true;
        }
    }

    private static void hookClassMethods(ClassLoader classLoader, String className, String[] methods) {
        if (classLoader == null) {
            return;
        }
        try {
            Class<?> clazz = classLoader.loadClass(className);
            hookClassMethods(clazz, className, methods);
        } catch (ClassNotFoundException e) {
            logInfo(className + " not present at install time");
        } catch (Throwable t) {
            logError("Failed to hook " + className + " - " + Log.getStackTraceString(t));
        }
    }

    private static void hookClassMethods(Class<?> clazz, String className, String[] methods) {
        if (clazz == null || className == null || methods == null) {
            return;
        }
        synchronized (CryptoToolHook.class) {
            int totalHooks = 0;
            logInfo("Scanning " + className);
            try {
                if (methods.length == 1 && HOOK_ALL_METHODS.equals(methods[0])) {
                    totalHooks = hookAllDeclaredMethods(clazz, className);
                    logInfo("Hooked " + className + "#* methods=" + totalHooks);
                } else {
                    for (String methodName : methods) {
                        XC_MethodHook hook = createClassMethodHook(className, methodName, clazz.getClassLoader());
                        int hooked = hookAllMethodsCompat(clazz, methodName, hook);
                        totalHooks += hooked;
                        logInfo("Hooked " + className + "#" + methodName + " methods=" + hooked);
                    }
                }
            } catch (Throwable t) {
                logError("Failed to hook " + className + " - " + Log.getStackTraceString(t));
            }
            if (totalHooks == 0) {
                logInfo("Hook warning: no methods hooked for " + className);
            }
        }
    }

    private static XC_MethodHook createClassMethodHook(final String className,
                                                       final String methodName,
                                                       final ClassLoader classLoader) {
        return new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                if (CLASS_CHECK_CODE.equals(className)
                        && "decheckcode".equals(methodName)
                        && Boolean.TRUE.equals(BANGCLE_SELF_DECODE.get())) {
                    return;
                }
                if (CLASS_CHECK_CODE.equals(className)) {
                    logInfo(className + "#" + methodName + " args=" + formatCheckCodeArgs(param.args));
                } else {
                    logInfo(className + "#" + methodName + " args=" + formatArgs(param.args));
                }
                if (CLASS_CRYPTO_TOOL.equals(className)) {
                    dumpNativeLibrariesOnce();
                }
                if (CLASS_CHECK_CODE.equals(className)
                        && ("checkcode".equals(methodName) || "decheckcode".equals(methodName))) {
                    dumpBangcleStaticSettings(classLoader);
                    dumpRuntimeEnvironment();
                }
            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (CLASS_CHECK_CODE.equals(className)
                        && "decheckcode".equals(methodName)
                        && Boolean.TRUE.equals(BANGCLE_SELF_DECODE.get())) {
                    return;
                }
                Object result = param.getResult();
                if (CLASS_CHECK_CODE.equals(className)) {
                    logInfo(className + "#" + methodName + " -> " + formatCheckCodeResult(result));
                } else {
                    logInfo(className + "#" + methodName + " -> " + formatValue(result));
                }

                if (!CLASS_CHECK_CODE.equals(className)) {
                    return;
                }
                if ("checkcode".equals(methodName) && result instanceof CharSequence) {
                    String envelope = ((CharSequence) result).toString();
                    logBangcleEnvelope(className + "#" + methodName + " envelope", envelope);
                    logBangcleDecryptedPlaintext(param.thisObject, envelope);
                } else if ("decheckcode".equals(methodName)
                        && param.args != null
                        && param.args.length > 0
                        && param.args[0] instanceof CharSequence) {
                    logBangcleEnvelope(className + "#" + methodName + " envelope",
                            ((CharSequence) param.args[0]).toString());
                }
            }
        };
    }

    private static int hookAllDeclaredMethods(Class<?> clazz, String className) throws Throwable {
        int hooked = 0;
        for (Method method : clazz.getDeclaredMethods()) {
            method.setAccessible(true);
            hookMember(method, createClassMethodHook(className, method.getName(), clazz.getClassLoader()));
            hooked += 1;
            logInfo("Hook catalog " + className + "#" + formatMethodSignature(method));
        }
        if (hooked == 0) {
            logInfo("No methods found for " + clazz.getName() + "#*");
        }
        return hooked;
    }

    private static int hookAllMethodsCompat(Class<?> clazz, String methodName, XC_MethodHook hook) throws Throwable {
        int hooked = 0;
        for (Class<?> current = clazz; current != null; current = current.getSuperclass()) {
            for (Method method : current.getDeclaredMethods()) {
                if (!methodName.equals(method.getName())) {
                    continue;
                }
                method.setAccessible(true);
                hookMember(method, hook);
                hooked += 1;
            }
        }
        if (hooked == 0) {
            logInfo("No methods found for " + clazz.getName() + "#" + methodName);
        }
        return hooked;
    }

    private static String formatMethodSignature(Method method) {
        if (method == null) {
            return "unknown";
        }
        StringBuilder sb = new StringBuilder();
        sb.append(method.getName()).append("(");
        Class<?>[] params = method.getParameterTypes();
        for (int i = 0; i < params.length; i++) {
            if (i > 0) {
                sb.append(",");
            }
            sb.append(formatTypeName(params[i]));
        }
        sb.append(")->").append(formatTypeName(method.getReturnType()));
        int modifiers = method.getModifiers();
        if (Modifier.isStatic(modifiers)) {
            sb.append(" [static]");
        }
        if (Modifier.isNative(modifiers)) {
            sb.append(" [native]");
        }
        return sb.toString();
    }

    private static String formatTypeName(Class<?> type) {
        if (type == null) {
            return "null";
        }
        if (!type.isArray()) {
            return type.getSimpleName();
        }
        int dimensions = 0;
        Class<?> current = type;
        while (current.isArray()) {
            dimensions += 1;
            current = current.getComponentType();
        }
        StringBuilder sb = new StringBuilder(current.getSimpleName());
        for (int i = 0; i < dimensions; i++) {
            sb.append("[]");
        }
        return sb.toString();
    }

    private static void hookMember(Member member, XC_MethodHook callback) throws Throwable {
        Method bridge = hookBridgeMethod;
        if (bridge == null) {
            bridge = XposedBridge.class.getDeclaredMethod(
                    "hookMethod",
                    Member.class,
                    XC_MethodHook.class
            );
            bridge.setAccessible(true);
            hookBridgeMethod = bridge;
        }
        bridge.invoke(null, member, callback);
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

    private static String formatCheckCodeArgs(Object[] args) {
        if (args == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < args.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            Object value = args[i];
            if (value instanceof CharSequence) {
                sb.append(summariseText((CharSequence) value));
            } else {
                sb.append(formatValue(value));
            }
        }
        sb.append("]");
        return sb.toString();
    }

    private static String formatCheckCodeResult(Object result) {
        if (result instanceof CharSequence) {
            return result.toString();
        }
        return formatValue(result);
    }

    private static String summariseText(CharSequence text) {
        if (text == null) {
            return "null";
        }
        return "len=" + text.length() + " text=" + text;
    }

    private static String formatValue(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof byte[]) {
            byte[] data = (byte[]) value;
            return "len=" + data.length + " hex=" + toHex(data);
        }
        if (value instanceof ByteBuffer) {
            byte[] data = copyBuffer((ByteBuffer) value);
            return "len=" + data.length + " hex=" + toHex(data);
        }
        if (value instanceof CharSequence) {
            return value.toString();
        }
        if (value.getClass().isArray()) {
            int length = Array.getLength(value);
            StringBuilder sb = new StringBuilder();
            sb.append(value.getClass().getSimpleName()).append("[").append(length).append("] [");
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

    private static byte[] copyBuffer(ByteBuffer buffer) {
        ByteBuffer duplicate = buffer.duplicate();
        int remaining = duplicate.remaining();
        if (remaining <= 0) {
            return new byte[0];
        }
        byte[] data = new byte[remaining];
        duplicate.get(data);
        return data;
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
                logInfo("Bangcle " + field.getName()
                        + " type=" + field.getType().getSimpleName()
                        + " value=" + describeBangcleValue(value));
            }
            settingsLogged = true;
        } catch (ClassNotFoundException e) {
            logInfo("BangcleKBSettings not yet available: " + e.getMessage());
        } catch (Throwable t) {
            logError("Failed dumping Bangcle settings - " + Log.getStackTraceString(t));
        }
    }

    private static String describeBangcleValue(Object value) {
        if (value instanceof CharSequence) {
            CharSequence text = (CharSequence) value;
            return "len=" + text.length() + " val=" + text;
        }
        return formatValue(value);
    }

    private static void dumpRuntimeEnvironment() {
        if (environmentLogged) {
            return;
        }
        environmentLogged = true;
        try {
            logInfo("Env Build.BOARD=" + Build.BOARD);
            logInfo("Env Build.BRAND=" + Build.BRAND);
            logInfo("Env Build.DEVICE=" + Build.DEVICE);
            logInfo("Env Build.DISPLAY=" + Build.DISPLAY);
            logInfo("Env Build.FINGERPRINT=" + Build.FINGERPRINT);
            logInfo("Env Build.HARDWARE=" + Build.HARDWARE);
            logInfo("Env Build.MANUFACTURER=" + Build.MANUFACTURER);
            logInfo("Env Build.MODEL=" + Build.MODEL);
            logInfo("Env Build.PRODUCT=" + Build.PRODUCT);
            logInfo("Env Build.TAGS=" + Build.TAGS);
            logInfo("Env Build.TYPE=" + Build.TYPE);
            logInfo("Env Build.USER=" + Build.USER);
            logInfo("Env Build.VERSION.SDK_INT=" + Build.VERSION.SDK_INT);
            logInfo("Env Build.VERSION.RELEASE=" + Build.VERSION.RELEASE);
        } catch (Throwable t) {
            logError("Env Build read failed - " + Log.getStackTraceString(t));
        }
        try {
            logInfo("Env Build.SERIAL=" + Build.SERIAL);
        } catch (Throwable t) {
            logError("Env Build.SERIAL read failed - " + Log.getStackTraceString(t));
        }
        try {
            String serial = getSystemProperty("ro.serialno", "unknown");
            logInfo("Env ro.serialno=" + serial);
        } catch (Throwable t) {
            logError("Env ro.serialno failed - " + Log.getStackTraceString(t));
        }
        try {
            Application app = getApplicationSafe();
            if (app != null) {
                String androidId = Settings.Secure.getString(app.getContentResolver(), Settings.Secure.ANDROID_ID);
                logInfo("Env ANDROID_ID=" + androidId);
            } else {
                logInfo("Env ANDROID_ID unavailable (no Application)");
            }
        } catch (Throwable t) {
            logError("Env ANDROID_ID failed - " + Log.getStackTraceString(t));
        }
    }

    private static String getSystemProperty(String key, String defaultValue) {
        try {
            Class<?> props = Class.forName("android.os.SystemProperties");
            Method get = props.getDeclaredMethod("get", String.class, String.class);
            get.setAccessible(true);
            Object value = get.invoke(null, key, defaultValue);
            return value != null ? String.valueOf(value) : defaultValue;
        } catch (Throwable t) {
            return defaultValue;
        }
    }

    private static boolean isMostlyPrintable(byte[] data) {
        if (data == null || data.length == 0) {
            return false;
        }
        int printable = 0;
        for (byte b : data) {
            int c = b & 0xff;
            if ((c >= 0x20 && c <= 0x7e) || c == 0x0a || c == 0x0d || c == 0x09) {
                printable += 1;
            }
        }
        return printable >= Math.max(8, (int) (data.length * 0.8));
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
                        method.setAccessible(true);
                        hookMember(method, new XC_MethodHook() {
                            @Override
                            protected void afterHookedMethod(MethodHookParam param) {
                                Object cipher = param.thisObject;
                                if (!(cipher instanceof javax.crypto.Cipher)) {
                                    return;
                                }
                                try {
                                    javax.crypto.Cipher c = (javax.crypto.Cipher) cipher;
                                    CipherContext ctx = new CipherContext();
                                    ctx.algorithm = safeAlgorithm(c);
                                    ctx.mode = argsToMode(param.args);
                                    ctx.keyHex = extractKeyHex(param.args);
                                    ctx.keyInfo = extractKeyInfo(param.args);
                                    ctx.ivHex = extractIvHex(c);
                                    CIPHER_CONTEXT.put(cipher, ctx);
                                    if (isTrackedAlgorithm(ctx.algorithm)) {
                                        String keyLabel = ctx.keyHex != null ? ctx.keyHex : ctx.keyInfo;
                                        logInfo("Cipher.init algo=" + ctx.algorithm + " mode=" + modeName(ctx.mode)
                                                + (keyLabel != null ? " key=" + keyLabel : "")
                                                + (ctx.ivHex != null ? " iv=" + ctx.ivHex : ""));
                                    }
                                } catch (Throwable t) {
                                    logError("Cipher.init hook failure - " + Log.getStackTraceString(t));
                                }
                            }
                        });
                    } else if ("doFinal".equals(name)) {
                        final Method target = method;
                        target.setAccessible(true);
                        hookMember(target, new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) {
                                prepareCipherOperation(param, target);
                            }

                            @Override
                            protected void afterHookedMethod(MethodHookParam param) {
                                logCipherOperation(param, target);
                            }
                        });
                    }
                }
                cipherHookInstalled = true;
            } catch (Throwable t) {
                logError("Failed to hook javax.crypto.Cipher - " + Log.getStackTraceString(t));
            }
        }
    }

    private static void hookOkHttp(ClassLoader classLoader) {
        if (okHttpHookInstalled || classLoader == null) {
            return;
        }
        synchronized (CryptoToolHook.class) {
            if (okHttpHookInstalled) {
                return;
            }
            int fallbackHooks = hookObfuscatedOkHttp(classLoader);
            if (fallbackHooks > 0) {
                okHttpHookInstalled = true;
                logInfo("Installed OkHttp fallback hooks count=" + fallbackHooks);
                return;
            }
            logInfo("OkHttp fallback hooks not installed");
        }
    }

    private static void hookMqtt(ClassLoader classLoader) {
        if (mqttHookInstalled || classLoader == null) {
            return;
        }
        synchronized (CryptoToolHook.class) {
            if (mqttHookInstalled) {
                return;
            }
            int hooks = 0;
            hooks += hookBydMqtt(classLoader);
            mqttHookInstalled = hooks > 0;
            if (hooks > 0) {
                logInfo("Installed MQTT hooks count=" + hooks);
            } else {
                logInfo("MQTT hooks not installed");
            }
        }
    }

    private static final String[] MQTT_PACKAGE_PREFIXES = {
            "com.byd.bydautolink",
            "com.byd.aeri.caranywhere"
    };

    private static int hookBydMqtt(ClassLoader classLoader) {
        int hooks = 0;
        for (String prefix : MQTT_PACKAGE_PREFIXES) {
            hooks += hookMqttSetup(classLoader, prefix + ".repository.mqtt.MqttUtil$g", "h");
            hooks += hookMqttSetup(classLoader, prefix + ".repository.mqtt.MqttUtil", "z");
            hooks += hookMqttPublish(classLoader, prefix + ".repository.mqtt.MqttUtil$g", "b");
        }
        return hooks;
    }

    private static int hookMqttSetup(ClassLoader classLoader, String className, String methodName) {
        if (classLoader == null || className == null || methodName == null) {
            return 0;
        }
        try {
            Class<?> clazz = classLoader.loadClass(className);
            return hookAllMethodsCompat(clazz, methodName, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (param == null || param.args == null) {
                        return;
                    }
                    String broker = "";
                    for (Object arg : param.args) {
                        if (arg instanceof CharSequence) {
                            broker = singleLine(arg.toString());
                            break;
                        }
                    }
                    if (broker.isEmpty()) {
                        return;
                    }
                    logInfo("MQTT_SETUP class=" + className
                            + " method=" + methodName
                            + " broker=" + broker);
                }
            });
        } catch (ClassNotFoundException ignored) {
            return 0;
        } catch (Throwable t) {
            logError("MQTT setup hook failed " + className + "#" + methodName
                    + " - " + Log.getStackTraceString(t));
            return 0;
        }
    }

    private static int hookMqttPublish(ClassLoader classLoader, String className, String methodName) {
        if (classLoader == null || className == null || methodName == null) {
            return 0;
        }
        try {
            Class<?> clazz = classLoader.loadClass(className);
            return hookAllMethodsCompat(clazz, methodName, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    if (param == null || param.args == null || param.args.length < 2) {
                        return;
                    }
                    if (!(param.args[0] instanceof CharSequence)) {
                        return;
                    }
                    String topic = singleLine(param.args[0].toString());
                    if (topic.isEmpty()) {
                        return;
                    }

                    String payloadText = mqttPayloadToText(param.args[1]);
                    if (payloadText.isEmpty()) {
                        return;
                    }

                    logInfo("MQTT_PUBLISH topic=" + topic
                            + " payload=len=" + payloadText.length()
                            + " text=" + payloadText);
                }
            });
        } catch (ClassNotFoundException ignored) {
            return 0;
        } catch (Throwable t) {
            logError("MQTT publish hook failed " + className + "#" + methodName
                    + " - " + Log.getStackTraceString(t));
            return 0;
        }
    }

    private static String mqttPayloadToText(Object payload) {
        if (payload == null) {
            return "";
        }
        if (payload instanceof CharSequence) {
            return singleLine(payload.toString());
        }
        if (payload instanceof byte[]) {
            byte[] data = (byte[]) payload;
            if (data.length == 0) {
                return "";
            }
            if (isMostlyPrintable(data)) {
                return singleLine(new String(data, StandardCharsets.UTF_8));
            }
            return toHex(data);
        }
        if (payload instanceof ByteBuffer) {
            return mqttPayloadToText(copyBuffer((ByteBuffer) payload));
        }
        return singleLine(String.valueOf(payload));
    }

    private static int hookObfuscatedOkHttp(ClassLoader classLoader) {
        List<String> classNames = enumerateDexClasses(classLoader);
        if (classNames.isEmpty()) {
            return 0;
        }
        int hooks = 0;
        for (String className : classNames) {
            if (className == null || !className.startsWith("okhttp3.")) {
                continue;
            }
            if (className.startsWith("okhttp3.internal.publicsuffix")) {
                continue;
            }
            try {
                Class<?> clazz = classLoader.loadClass(className);
                int modifiers = clazz.getModifiers();
                if (clazz.isInterface() || Modifier.isAbstract(modifiers)) {
                    continue;
                }
                for (Method method : clazz.getDeclaredMethods()) {
                    if (!looksLikeCallExecutionMethod(method)) {
                        continue;
                    }
                    final Method target = method;
                    target.setAccessible(true);
                    hookMember(target, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            try {
                                Object response = param.getResult();
                                if (response == null || !isOkHttpResponseLike(response.getClass())) {
                                    return;
                                }
                                logHttpExchange(response, classLoader);
                            } catch (Throwable t) {
                                logError("OkHttp fallback hook failure - " + Log.getStackTraceString(t));
                            }
                        }
                    });
                    hooks += 1;
                    logInfo("OkHttp fallback hook " + clazz.getName() + "#" + target.getName());
                }
            } catch (Throwable ignored) {
                // continue
            }
        }
        return hooks;
    }

    private static boolean looksLikeCallExecutionMethod(Method method) {
        if (method == null || Modifier.isStatic(method.getModifiers())) {
            return false;
        }
        if (method.getParameterTypes().length != 0) {
            return false;
        }
        Class<?> returnType = method.getReturnType();
        if (returnType == null || returnType.isPrimitive() || !returnType.getName().startsWith("okhttp3.")) {
            return false;
        }
        if ("execute".equals(method.getName())) {
            return true;
        }
        for (Class<?> ex : method.getExceptionTypes()) {
            if (IOException.class.isAssignableFrom(ex)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isOkHttpResponseLike(Class<?> type) {
        if (type == null || !type.getName().startsWith("okhttp3.")) {
            return false;
        }
        boolean hasCodeLike = false;
        boolean hasPeekLike = false;
        for (Method method : type.getDeclaredMethods()) {
            if (Modifier.isStatic(method.getModifiers())) {
                continue;
            }
            if (method.getParameterTypes().length == 0 && method.getReturnType() == int.class) {
                hasCodeLike = true;
            }
            if (method.getParameterTypes().length == 1
                    && method.getParameterTypes()[0] == long.class
                    && method.getReturnType() != null
                    && method.getReturnType().getName().startsWith("okhttp3.")) {
                hasPeekLike = true;
            }
            if ("peekBody".equals(method.getName())) {
                return true;
            }
        }
        return hasCodeLike && hasPeekLike;
    }

    private static List<String> enumerateDexClasses(ClassLoader loader) {
        List<String> classes = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        try {
            Class<?> baseDexClassLoader = Class.forName("dalvik.system.BaseDexClassLoader");
            if (!baseDexClassLoader.isInstance(loader)) {
                return classes;
            }
            Field pathListField = findField(baseDexClassLoader, "pathList");
            if (pathListField == null) {
                return classes;
            }
            Object pathList = pathListField.get(loader);
            if (pathList == null) {
                return classes;
            }
            Field dexElementsField = findField(pathList.getClass(), "dexElements");
            if (dexElementsField == null) {
                return classes;
            }
            Object[] dexElements = (Object[]) dexElementsField.get(pathList);
            if (dexElements == null) {
                return classes;
            }
            for (Object element : dexElements) {
                if (element == null) {
                    continue;
                }
                Field dexFileField = findField(element.getClass(), "dexFile");
                if (dexFileField == null) {
                    continue;
                }
                Object dexFile = dexFileField.get(element);
                if (dexFile == null) {
                    continue;
                }
                Method entriesMethod = dexFile.getClass().getDeclaredMethod("entries");
                entriesMethod.setAccessible(true);
                Object entriesObj = entriesMethod.invoke(dexFile);
                if (!(entriesObj instanceof java.util.Enumeration)) {
                    continue;
                }
                @SuppressWarnings("unchecked")
                java.util.Enumeration<String> entries = (java.util.Enumeration<String>) entriesObj;
                while (entries.hasMoreElements()) {
                    String className = entries.nextElement();
                    if (className != null && seen.add(className)) {
                        classes.add(className);
                    }
                }
            }
        } catch (Throwable t) {
            logError("OkHttp class enumeration failed - " + Log.getStackTraceString(t));
        }
        return classes;
    }

    private static Field findField(Class<?> type, String name) {
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            try {
                Field field = current.getDeclaredField(name);
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException ignored) {
                // continue
            }
        }
        return null;
    }

    private static void logHttpExchange(Object response, ClassLoader classLoader) {
        Object request = invokeNoArg(response, "request");
        if (request == null) {
            request = findLikelyRequestObject(response);
        }
        if (request == null) {
            return;
        }

        String method = safeToString(invokeNoArg(request, "method"));
        String url = safeToString(invokeNoArg(request, "url"));
        String requestSummary = safeToString(request);
        if (method.isEmpty()) {
            method = firstRegexGroup(requestSummary, "method=([A-Z]+)");
        }
        if (url.isEmpty()) {
            url = firstRegexGroup(requestSummary, "url=([^,}\\s]+)");
        }
        if (!"POST".equalsIgnoreCase(method)) {
            return;
        }

        String requestHeaders = resolveHeaders(request);
        Object requestBodyObj = invokeNoArg(request, "body");
        if (requestBodyObj == null) {
            requestBodyObj = findLikelyRequestBodyObject(request);
        }
        byte[] requestBody = readRequestBodyBytes(requestBodyObj, classLoader);

        int statusCode = asInt(invokeNoArg(response, "code"), -1);
        String responseSummary = safeToString(response);
        if (statusCode < 0) {
            String parsed = firstRegexGroup(responseSummary, "code=([0-9]{3})");
            if (!parsed.isEmpty()) {
                try {
                    statusCode = Integer.parseInt(parsed);
                } catch (NumberFormatException ignored) {
                    // ignore
                }
            }
        }
        byte[] responseBody = readResponseBodyBytes(response);

        String requestBodyText = requestBody != null
                ? formatHttpBody(requestBody)
                : "unavailable";
        String responseBodyText = responseBody != null
                ? formatHttpBody(responseBody)
                : "unavailable";

        String line = "HTTP method=POST"
                + " url=" + singleLine(url)
                + " reqHeaders=" + singleLine(requestHeaders)
                + " reqBody=" + singleLine(requestBodyText)
                + " respCode=" + statusCode
                + " respBody=" + singleLine(responseBodyText);
        logInfo(line);
    }

    private static byte[] readRequestBodyBytes(Object requestBody, ClassLoader classLoader) {
        if (requestBody == null) {
            return null;
        }
        if (asBoolean(invokeNoArg(requestBody, "isDuplex"), false)) {
            return null;
        }
        if (asBoolean(invokeNoArg(requestBody, "isOneShot"), false)) {
            return null;
        }

        byte[] directBytes = tryReadBodyViaNoArgMethods(requestBody);
        if (directBytes != null && directBytes.length > 0) {
            return directBytes;
        }

        byte[] fieldBytes = tryReadBodyViaFields(requestBody);
        if (fieldBytes != null && fieldBytes.length > 0) {
            return fieldBytes;
        }

        Method writeTo = findSingleArgMethod(requestBody.getClass(), "writeTo");
        if (writeTo == null) {
            writeTo = findLikelyWriteToMethod(requestBody.getClass());
        }
        if (writeTo == null) {
            return null;
        }
        Class<?> sinkType = writeTo.getParameterTypes()[0];
        Object buffer = createOkioBuffer(sinkType, classLoader);
        if (buffer == null || !sinkType.isInstance(buffer)) {
            return null;
        }

        try {
            writeTo.setAccessible(true);
            writeTo.invoke(requestBody, buffer);
            return readOkioBufferBytes(buffer, HTTP_BODY_CAPTURE_LIMIT);
        } catch (Throwable t) {
            logError("HTTP request body capture failed - " + Log.getStackTraceString(t));
            return null;
        }
    }

    private static byte[] tryReadBodyViaNoArgMethods(Object requestBody) {
        if (requestBody == null) {
            return null;
        }
        for (Class<?> current = requestBody.getClass(); current != null && current != Object.class; current = current.getSuperclass()) {
            for (Method method : current.getDeclaredMethods()) {
                if (Modifier.isStatic(method.getModifiers()) || method.getParameterTypes().length != 0) {
                    continue;
                }
                if (shouldSkipNoArgMethod(method)) {
                    continue;
                }
                Class<?> returnType = method.getReturnType();
                if (returnType != byte[].class && returnType != String.class) {
                    continue;
                }
                try {
                    method.setAccessible(true);
                    Object value = method.invoke(requestBody);
                    if (value instanceof byte[]) {
                        byte[] data = (byte[]) value;
                        if (data.length > 0) {
                            return data.length > HTTP_BODY_CAPTURE_LIMIT
                                    ? Arrays.copyOf(data, (int) HTTP_BODY_CAPTURE_LIMIT)
                                    : data;
                        }
                    } else if (value instanceof String) {
                        String text = (String) value;
                        if (isLikelyBodyText(text)) {
                            byte[] data = text.getBytes(StandardCharsets.UTF_8);
                            return data.length > HTTP_BODY_CAPTURE_LIMIT
                                    ? Arrays.copyOf(data, (int) HTTP_BODY_CAPTURE_LIMIT)
                                    : data;
                        }
                    }
                } catch (Throwable ignored) {
                    // continue
                }
            }
        }
        return null;
    }

    private static byte[] tryReadBodyViaFields(Object requestBody) {
        if (requestBody == null) {
            return null;
        }
        for (Class<?> current = requestBody.getClass(); current != null && current != Object.class; current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers())) {
                    continue;
                }
                try {
                    field.setAccessible(true);
                    Object value = field.get(requestBody);
                    if (value == null) {
                        continue;
                    }
                    if (value instanceof byte[]) {
                        byte[] data = (byte[]) value;
                        if (data.length > 0) {
                            return data.length > HTTP_BODY_CAPTURE_LIMIT
                                    ? Arrays.copyOf(data, (int) HTTP_BODY_CAPTURE_LIMIT)
                                    : data;
                        }
                    }
                    if (value instanceof String) {
                        String text = (String) value;
                        if (isLikelyBodyText(text)) {
                            byte[] data = text.getBytes(StandardCharsets.UTF_8);
                            return data.length > HTTP_BODY_CAPTURE_LIMIT
                                    ? Arrays.copyOf(data, (int) HTTP_BODY_CAPTURE_LIMIT)
                                    : data;
                        }
                    }
                    if (value instanceof ByteBuffer) {
                        byte[] data = copyBuffer((ByteBuffer) value);
                        if (data.length > 0) {
                            return data.length > HTTP_BODY_CAPTURE_LIMIT
                                    ? Arrays.copyOf(data, (int) HTTP_BODY_CAPTURE_LIMIT)
                                    : data;
                        }
                    }
                    byte[] nested = tryReadBodyViaNoArgMethods(value);
                    if (nested != null && nested.length > 0) {
                        return nested;
                    }
                } catch (Throwable ignored) {
                    // continue
                }
            }
        }
        return null;
    }

    private static boolean shouldSkipNoArgMethod(Method method) {
        if (method == null) {
            return true;
        }
        String name = method.getName();
        return "toString".equals(name)
                || "hashCode".equals(name)
                || "getClass".equals(name)
                || "clone".equals(name)
                || "finalize".equals(name);
    }

    private static boolean isLikelyBodyText(String text) {
        if (text == null) {
            return false;
        }
        String value = text.trim();
        if (value.isEmpty()) {
            return false;
        }
        if (value.matches("^[A-Za-z0-9_.$]+@[0-9a-fA-F]+$")) {
            return false;
        }
        if (value.startsWith("{") || value.startsWith("[") || value.startsWith("F{")) {
            return true;
        }
        return value.contains("\"request\"")
                || value.contains("\"response\"")
                || value.contains("content-type")
                || value.contains("application/json");
    }

    private static String resolveHeaders(Object owner) {
        if (owner == null) {
            return "";
        }
        String headers = safeToString(invokeNoArg(owner, "headers"));
        if (headers.isEmpty()) {
            headers = safeToString(owner);
        }
        String extracted = extractHeadersFromSummary(headers);
        if (!extracted.isEmpty()) {
            headers = extracted;
        }
        headers = singleLine(headers);
        return looksLikeHeaderLine(headers) ? headers : "";
    }

    private static String extractHeadersFromSummary(String summary) {
        if (summary == null || summary.isEmpty()) {
            return "";
        }
        String value = summary;
        if (value.startsWith("Request{") || value.startsWith("Response{")) {
            value = singleLine(value);
        }
        String headers = firstRegexGroup(value, "headers=\\[(.*?)]");
        if (headers.isEmpty()) {
            headers = firstRegexGroup(value, "headers:\\s*\\[(.*?)]");
        }
        return headers;
    }

    private static boolean looksLikeHeaderLine(String text) {
        if (text == null) {
            return false;
        }
        String value = text.trim();
        if (value.isEmpty()) {
            return false;
        }
        String lower = value.toLowerCase(Locale.ROOT);
        if (!(lower.contains(":") || lower.contains("="))) {
            return false;
        }
        return lower.contains("user-agent")
                || lower.contains("content-type")
                || lower.contains("content-length")
                || lower.contains("accept")
                || lower.contains("host")
                || lower.contains("cookie")
                || lower.contains("authorization");
    }

    private static byte[] readResponseBodyBytes(Object response) {
        if (response == null) {
            return null;
        }
        try {
            Method peekBody = findMethod(response.getClass(), "peekBody", long.class);
            if (peekBody == null) {
                peekBody = findLikelyPeekBodyMethod(response.getClass());
            }
            if (peekBody == null) {
                return null;
            }
            Object bodyCopy = peekBody.invoke(response, HTTP_BODY_CAPTURE_LIMIT);
            if (bodyCopy == null) {
                return null;
            }
            Object bytes = invokeNoArg(bodyCopy, "bytes");
            if (bytes instanceof byte[]) {
                return (byte[]) bytes;
            }
            Object bytesFallback = invokeNoArgReturningType(bodyCopy, byte[].class);
            if (bytesFallback instanceof byte[]) {
                return (byte[]) bytesFallback;
            }
            Object text = invokeNoArg(bodyCopy, "string");
            if (text instanceof String) {
                return ((String) text).getBytes(StandardCharsets.UTF_8);
            }
            Object textFallback = invokeNoArgReturningType(bodyCopy, String.class);
            if (textFallback instanceof String) {
                return ((String) textFallback).getBytes(StandardCharsets.UTF_8);
            }
        } catch (Throwable t) {
            logError("HTTP response body capture failed - " + Log.getStackTraceString(t));
        }
        return null;
    }

    private static Object createOkioBuffer(Class<?> sinkType, ClassLoader fallbackLoader) {
        ClassLoader[] loaders = new ClassLoader[]{
                sinkType != null ? sinkType.getClassLoader() : null,
                fallbackLoader,
                CryptoToolHook.class.getClassLoader()
        };
        for (ClassLoader loader : loaders) {
            if (loader == null) {
                continue;
            }
            try {
                Class<?> bufferClass = Class.forName("okio.Buffer", false, loader);
                return bufferClass.getDeclaredConstructor().newInstance();
            } catch (Throwable ignored) {
                // continue
            }
        }
        return null;
    }

    private static byte[] readOkioBufferBytes(Object buffer, long maxBytes) {
        if (buffer == null) {
            return null;
        }
        try {
            long available = asLong(invokeNoArg(buffer, "size"), 0L);
            long limit = available > 0 ? Math.min(available, maxBytes) : maxBytes;

            Method readByteArrayWithLen = findMethod(buffer.getClass(), "readByteArray", long.class);
            if (readByteArrayWithLen != null) {
                Object out = readByteArrayWithLen.invoke(buffer, limit);
                if (out instanceof byte[]) {
                    return (byte[]) out;
                }
            }

            Method readByteArray = findMethod(buffer.getClass(), "readByteArray");
            if (readByteArray != null) {
                Object out = readByteArray.invoke(buffer);
                if (out instanceof byte[]) {
                    byte[] data = (byte[]) out;
                    if (data.length > maxBytes) {
                        return Arrays.copyOf(data, (int) maxBytes);
                    }
                    return data;
                }
            }
        } catch (Throwable t) {
            logError("okio.Buffer read failed - " + Log.getStackTraceString(t));
        }
        return null;
    }

    private static Method findSingleArgMethod(Class<?> type, String methodName) {
        if (type == null) {
            return null;
        }
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            for (Method method : current.getDeclaredMethods()) {
                if (methodName.equals(method.getName()) && method.getParameterTypes().length == 1) {
                    return method;
                }
            }
        }
        return null;
    }

    private static Method findLikelyWriteToMethod(Class<?> type) {
        if (type == null) {
            return null;
        }
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            for (Method method : current.getDeclaredMethods()) {
                if (Modifier.isStatic(method.getModifiers())) {
                    continue;
                }
                if (method.getParameterTypes().length != 1 || method.getReturnType() != Void.TYPE) {
                    continue;
                }
                for (Class<?> ex : method.getExceptionTypes()) {
                    if (IOException.class.isAssignableFrom(ex)) {
                        method.setAccessible(true);
                        return method;
                    }
                }
            }
        }
        return null;
    }

    private static Method findLikelyPeekBodyMethod(Class<?> type) {
        if (type == null) {
            return null;
        }
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            for (Method method : current.getDeclaredMethods()) {
                if (Modifier.isStatic(method.getModifiers())) {
                    continue;
                }
                Class<?>[] params = method.getParameterTypes();
                if (params.length != 1 || params[0] != long.class) {
                    continue;
                }
                Class<?> returnType = method.getReturnType();
                if (returnType != null && returnType.getName().startsWith("okhttp3.")) {
                    method.setAccessible(true);
                    return method;
                }
            }
        }
        return null;
    }

    private static Object findLikelyRequestObject(Object response) {
        if (response == null) {
            return null;
        }
        for (Method method : response.getClass().getDeclaredMethods()) {
            if (Modifier.isStatic(method.getModifiers()) || method.getParameterTypes().length != 0) {
                continue;
            }
            Class<?> returnType = method.getReturnType();
            if (returnType == null || returnType.isPrimitive() || !returnType.getName().startsWith("okhttp3.")) {
                continue;
            }
            try {
                method.setAccessible(true);
                Object value = method.invoke(response);
                if (value == null) {
                    continue;
                }
                String text = String.valueOf(value);
                if (text.contains("Request{") || text.contains("method=") || text.contains("url=")) {
                    return value;
                }
            } catch (Throwable ignored) {
                // continue
            }
        }
        return null;
    }

    private static Object findLikelyRequestBodyObject(Object request) {
        if (request == null) {
            return null;
        }
        for (Method method : request.getClass().getDeclaredMethods()) {
            if (Modifier.isStatic(method.getModifiers()) || method.getParameterTypes().length != 0) {
                continue;
            }
            Class<?> returnType = method.getReturnType();
            if (returnType == null || returnType.isPrimitive()) {
                continue;
            }
            try {
                method.setAccessible(true);
                Object value = method.invoke(request);
                if (value == null) {
                    continue;
                }
                if (findSingleArgMethod(value.getClass(), "writeTo") != null
                        || findLikelyWriteToMethod(value.getClass()) != null) {
                    return value;
                }
            } catch (Throwable ignored) {
                // continue
            }
        }
        return null;
    }

    private static Object invokeNoArgReturningType(Object target, Class<?> expectedReturnType) {
        if (target == null || expectedReturnType == null) {
            return null;
        }
        for (Method method : target.getClass().getDeclaredMethods()) {
            if (Modifier.isStatic(method.getModifiers()) || method.getParameterTypes().length != 0) {
                continue;
            }
            if (method.getReturnType() != expectedReturnType) {
                continue;
            }
            try {
                method.setAccessible(true);
                return method.invoke(target);
            } catch (Throwable ignored) {
                // continue
            }
        }
        return null;
    }

    private static String firstRegexGroup(String value, String regex) {
        if (value == null || value.isEmpty() || regex == null || regex.isEmpty()) {
            return "";
        }
        try {
            Matcher matcher = Pattern.compile(regex).matcher(value);
            if (matcher.find() && matcher.groupCount() >= 1) {
                String out = matcher.group(1);
                return out == null ? "" : out;
            }
        } catch (Throwable ignored) {
            // ignore
        }
        return "";
    }

    private static Method findMethod(Class<?> type, String name, Class<?>... paramTypes) {
        if (type == null) {
            return null;
        }
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            try {
                Method method = current.getDeclaredMethod(name, paramTypes);
                method.setAccessible(true);
                return method;
            } catch (NoSuchMethodException ignored) {
                // continue
            }
        }
        return null;
    }

    private static Object invokeNoArg(Object target, String methodName) {
        if (target == null) {
            return null;
        }
        Method method = findMethod(target.getClass(), methodName);
        if (method == null) {
            return null;
        }
        try {
            return method.invoke(target);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String formatHttpBody(byte[] body) {
        if (body == null) {
            return "len=0";
        }
        if (isMostlyPrintable(body)) {
            return "len=" + body.length + " text=" + new String(body, StandardCharsets.UTF_8);
        }
        return "len=" + body.length + " hex=" + toHex(body);
    }

    private static String singleLine(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        String normalised = value.replace('\n', ' ')
                .replace('\r', ' ')
                .replace('\t', ' ');
        return normalised.trim().replaceAll("\\s{2,}", " ");
    }

    private static String safeToString(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private static int asInt(Object value, int fallback) {
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        return fallback;
    }

    private static long asLong(Object value, long fallback) {
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        return fallback;
    }

    private static boolean asBoolean(Object value, boolean fallback) {
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        return fallback;
    }

    private static void prepareCipherOperation(XC_MethodHook.MethodHookParam param, Method method) {
        CipherContext ctx = CIPHER_CONTEXT.get(param.thisObject);
        if (ctx == null || !isTrackedAlgorithm(ctx.algorithm)) {
            return;
        }
        if (method == null) {
            return;
        }
        ctx.pendingInvocation = buildInvocation(method, param.args);
    }

    private static void logCipherOperation(XC_MethodHook.MethodHookParam param, Method method) {
        CipherContext ctx = CIPHER_CONTEXT.get(param.thisObject);
        if (ctx == null || !isTrackedAlgorithm(ctx.algorithm)) {
            return;
        }
        CipherInvocation invocation = ctx.pendingInvocation;
        ctx.pendingInvocation = null;
        if (invocation == null) {
            invocation = new CipherInvocation();
            invocation.methodName = method != null ? method.getName() : "doFinal";
        }

        byte[] output = null;
        Object result = param.getResult();
        if (result instanceof byte[]) {
            output = (byte[]) result;
        } else if (result instanceof ByteBuffer) {
            output = copyBuffer((ByteBuffer) result);
        }
        if (output == null) {
            return;
        }

        String baseLabel = "Cipher." + invocation.methodName
                + " algo=" + ctx.algorithm
                + " mode=" + modeName(ctx.mode);
        String keyLabel = ctx.keyHex != null ? ctx.keyHex : ctx.keyInfo;
        if (keyLabel != null) {
            baseLabel += " key=" + keyLabel;
        }
        if (ctx.ivHex != null) {
            baseLabel += " iv=" + ctx.ivHex;
        }
        if (invocation.inputBytes != null) {
            baseLabel += " inputBase64=" + Base64.encodeToString(invocation.inputBytes, Base64.NO_WRAP);
        }
        baseLabel += " outputBase64=" + Base64.encodeToString(output, Base64.NO_WRAP);
        logInfo(baseLabel);
    }

    private static CipherInvocation buildInvocation(Method method, Object[] args) {
        CipherInvocation invocation = new CipherInvocation();
        invocation.methodName = method.getName();
        invocation.inputBytes = resolveCipherInput(args);
        return invocation;
    }

    private static byte[] resolveCipherInput(Object[] args) {
        if (args == null || args.length == 0) {
            return null;
        }
        Object first = args[0];
        if (first instanceof byte[]) {
            byte[] data = (byte[]) first;
            if (args.length >= 3 && args[1] instanceof Integer && args[2] instanceof Integer) {
                int offset = (Integer) args[1];
                int len = (Integer) args[2];
                if (offset < 0 || len <= 0 || offset + len > data.length) {
                    return data;
                }
                return Arrays.copyOfRange(data, offset, offset + len);
            }
            return data;
        }
        if (first instanceof ByteBuffer) {
            return copyBuffer((ByteBuffer) first);
        }
        return null;
    }

    private static String safeAlgorithm(javax.crypto.Cipher cipher) {
        try {
            return cipher.getAlgorithm();
        } catch (Throwable t) {
            return "unknown";
        }
    }

    private static int argsToMode(Object[] args) {
        if (args != null && args.length > 0 && args[0] instanceof Integer) {
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
                } catch (Throwable ignored) {
                    // ignore
                }
            }
        }
        return null;
    }

    private static String extractKeyInfo(Object[] args) {
        if (args == null) {
            return null;
        }
        for (Object arg : args) {
            if (arg instanceof java.security.Key) {
                try {
                    java.security.Key key = (java.security.Key) arg;
                    String algorithm = key.getAlgorithm();
                    String format = key.getFormat();
                    byte[] encoded = key.getEncoded();
                    StringBuilder sb = new StringBuilder();
                    if (algorithm != null) {
                        sb.append(algorithm);
                    }
                    if (format != null) {
                        if (sb.length() > 0) {
                            sb.append("/");
                        }
                        sb.append(format);
                    }
                    if (encoded != null) {
                        sb.append("/len=").append(encoded.length);
                    }
                    return sb.length() > 0 ? sb.toString() : key.getClass().getSimpleName();
                } catch (Throwable ignored) {
                    return arg.getClass().getSimpleName();
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
        } catch (Throwable ignored) {
            // ignore
        }
        return null;
    }

    private static boolean isTrackedAlgorithm(String algorithm) {
        return algorithm != null && (
                algorithm.contains("AES")
                        || algorithm.contains("SM4")
                        || algorithm.contains("RSA")
                        || algorithm.contains("SM2")
                        || algorithm.contains("ECIES")
        );
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

    private static void logBangcleEnvelope(String label, String base64) {
        if (base64 == null) {
            return;
        }
        try {
            String cleaned = sanitiseBase64(base64);
            if (cleaned.length() == 0) {
                return;
            }
            String[] candidates;
            if (cleaned.length() > 1) {
                char first = cleaned.charAt(0);
                boolean hasTaggedPrefix = first == 'F';
                if (hasTaggedPrefix) {
                    candidates = new String[]{cleaned, cleaned.substring(1)};
                } else {
                    candidates = new String[]{cleaned};
                }
            } else {
                candidates = new String[]{cleaned};
            }
            byte[] decoded = null;
            IllegalArgumentException lastError = null;
            for (String candidate : candidates) {
                String padded = candidate;
                int remainder = padded.length() % 4;
                if (remainder != 0) {
                    padded += "====".substring(remainder);
                }
                try {
                    decoded = Base64.decode(padded, Base64.NO_WRAP);
                    break;
                } catch (IllegalArgumentException e) {
                    lastError = e;
                }
                try {
                    decoded = Base64.decode(padded, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
                    break;
                } catch (IllegalArgumentException e) {
                    lastError = e;
                }
                try {
                    decoded = Base64.decode(padded, Base64.DEFAULT);
                    break;
                } catch (IllegalArgumentException e) {
                    lastError = e;
                }
            }
            if (decoded == null) {
                logError(label + " base64 decode failed len=" + cleaned.length()
                        + " text=" + cleaned
                        + " err=" + (lastError != null ? lastError.getMessage() : "unknown"));
                return;
            }
            if (decoded.length < 17) {
                logInfo(label + " len=" + decoded.length + " (too short)");
                return;
            }
            int version = decoded[0] & 0xff;
            byte[] iv = Arrays.copyOfRange(decoded, 1, 17);
            int cipherLen = decoded.length - 17;
            int trailerLen = cipherLen % 16;
            int tailSampleStart = Math.max(17, decoded.length - 32);
            byte[] tailSample = Arrays.copyOfRange(decoded, tailSampleStart, decoded.length);
            logInfo(label + " version=0x" + Integer.toHexString(version)
                    + " total=" + decoded.length
                    + " cipher=" + cipherLen
                    + " trailer=" + trailerLen
                    + " iv=" + toHex(iv)
                    + " tail=" + toHex(tailSample));
        } catch (Throwable t) {
            logError(label + " parse failed - " + Log.getStackTraceString(t));
        }
    }

    private static String sanitiseBase64(String raw) {
        String trimmed = raw == null ? "" : raw.trim();
        if (trimmed.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(trimmed.length());
        for (int i = 0; i < trimmed.length(); i++) {
            char ch = trimmed.charAt(i);
            if (ch == '-' || ch == '_') {
                sb.append(ch == '-' ? '+' : '/');
                continue;
            }
            if ((ch >= 'A' && ch <= 'Z')
                    || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9')
                    || ch == '+'
                    || ch == '/'
                    || ch == '=') {
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    private static void logBangcleDecryptedPlaintext(Object target, String base64) {
        if (target == null || base64 == null || base64.isEmpty()) {
            return;
        }
        if (Boolean.TRUE.equals(BANGCLE_SELF_DECODE.get())) {
            return;
        }
        try {
            BANGCLE_SELF_DECODE.set(Boolean.TRUE);
            Method method = target.getClass().getDeclaredMethod("decheckcode", String.class);
            method.setAccessible(true);
            Object decrypted = method.invoke(target, base64);
            if (!(decrypted instanceof CharSequence)) {
                return;
            }
            byte[] raw = decrypted.toString().getBytes(StandardCharsets.ISO_8859_1);
            logInfo("CheckCodeUtil#checkcode plaintext bytes len=" + raw.length + " hex=" + toHex(raw));
        } catch (Throwable t) {
            logError("CheckCodeUtil#checkcode decrypt probe failed - " + Log.getStackTraceString(t));
        } finally {
            BANGCLE_SELF_DECODE.set(Boolean.FALSE);
        }
    }

    private static void dumpNativeLibrariesOnce() {
        synchronized (CryptoToolHook.class) {
            if (nativeDumped) {
                return;
            }
            nativeDumped = true;
        }

        try {
            Application app = getApplicationSafe();
            if (app == null) {
                logError("Native dump skipped - application context missing");
                return;
            }
            File outDir = new File(app.getFilesDir(), "byd-native-dumps");
            if (!outDir.exists() && !outDir.mkdirs()) {
                logError("Native dump skipped - cannot create " + outDir.getAbsolutePath());
                return;
            }
            Map<String, List<MapSegment>> segments = collectNativeSegments();
            if (segments.isEmpty()) {
                logInfo("Native dump: no candidate segments found");
                return;
            }
            for (Map.Entry<String, List<MapSegment>> entry : segments.entrySet()) {
                dumpNativeLibrary(entry.getKey(), entry.getValue(), outDir);
            }
            logInfo("Native dump complete");
        } catch (Throwable t) {
            logError("Native dump failed - " + Log.getStackTraceString(t));
        }
    }

    private static Map<String, List<MapSegment>> collectNativeSegments() throws IOException {
        Map<String, List<MapSegment>> segments = new HashMap<>();
        File maps = new File("/proc/self/maps");
        if (!maps.exists()) {
            return segments;
        }
        String[] hints = new String[]{
                "bangcle",
                "safe",
                "protect",
                "encrypt",
                "dex",
                "wbsk",
                "app.so"
        };
        try (BufferedReader reader = new BufferedReader(new FileReader(maps))) {
            String line;
            while ((line = reader.readLine()) != null) {
                MapSegment segment = parseMapSegment(line);
                if (segment == null || segment.path == null || !segment.path.endsWith(".so")) {
                    continue;
                }
                String lower = segment.path.toLowerCase(Locale.ROOT);
                boolean match = false;
                for (String hint : hints) {
                    if (lower.contains(hint)) {
                        match = true;
                        break;
                    }
                }
                if (!match) {
                    continue;
                }
                List<MapSegment> list = segments.get(segment.path);
                if (list == null) {
                    list = new ArrayList<>();
                    segments.put(segment.path, list);
                }
                list.add(segment);
            }
        }
        return segments;
    }

    private static MapSegment parseMapSegment(String line) {
        String[] parts = line.trim().split("\\s+");
        if (parts.length < 6) {
            return null;
        }
        String[] range = parts[0].split("-");
        if (range.length != 2) {
            return null;
        }
        String perms = parts[1];
        if (perms.length() < 1 || perms.charAt(0) != 'r') {
            return null;
        }
        long start = parseHex(range[0]);
        long end = parseHex(range[1]);
        long offset = parseHex(parts[2]);
        if (start <= 0 || end <= start) {
            return null;
        }
        return new MapSegment(start, end, offset, parts[5]);
    }

    private static long parseHex(String value) {
        try {
            return Long.parseLong(value, 16);
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    private static void dumpNativeLibrary(String path, List<MapSegment> segments, File outDir) {
        if (segments == null || segments.isEmpty()) {
            return;
        }
        long maxSize = 0;
        for (MapSegment segment : segments) {
            long end = segment.offset + (segment.end - segment.start);
            if (end > maxSize) {
                maxSize = end;
            }
        }

        LibcoreMemoryReader reader = LibcoreMemoryReader.create();
        if (reader == null) {
            logError("Native dump unavailable for " + path);
            return;
        }

        String fileName = new File(path).getName();
        File outFile = new File(outDir, fileName + ".mem.so");
        logInfo("Native dump active for " + path + " using " + reader.name());

        try (RandomAccessFile out = new RandomAccessFile(outFile, "rw")) {
            out.setLength(maxSize);
            byte[] buffer = new byte[64 * 1024];
            for (MapSegment segment : segments) {
                long remaining = segment.end - segment.start;
                long inPos = segment.start;
                long outPos = segment.offset;
                while (remaining > 0) {
                    int chunk = (int) Math.min(buffer.length, remaining);
                    int read = reader.read(inPos, buffer, chunk);
                    if (read <= 0) {
                        break;
                    }
                    out.seek(outPos);
                    out.write(buffer, 0, read);
                    inPos += read;
                    outPos += read;
                    remaining -= read;
                }
            }
            logInfo("Native dump saved " + outFile.getAbsolutePath() + " size=" + maxSize);
        } catch (Throwable t) {
            logError("Native dump failed for " + path + " - " + Log.getStackTraceString(t));
        }
    }

    private static Application getApplicationSafe() {
        try {
            Class<?> activityThread = Class.forName("android.app.ActivityThread");
            Method currentApplication = activityThread.getDeclaredMethod("currentApplication");
            return (Application) currentApplication.invoke(null);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static void logInfo(String message) {
        logLine(Log.INFO, message);
    }

    private static void logError(String message) {
        logLine(Log.ERROR, message);
    }

    private static synchronized void logLine(int level, String message) {
        if (message == null) {
            return;
        }
        if (message.length() <= LOGCAT_CHUNK_LIMIT) {
            if (level == Log.ERROR) {
                Log.e(TAG, message);
            } else {
                Log.i(TAG, message);
            }
            return;
        }

        int id = LOG_SEQUENCE.incrementAndGet();
        final int chunkSize = 3000;
        int total = (message.length() + chunkSize - 1) / chunkSize;
        for (int i = 0; i < total; i++) {
            int start = i * chunkSize;
            int end = Math.min(message.length(), start + chunkSize);
            String part = message.substring(start, end);
            String prefix = "CHUNK " + id + " " + (i + 1) + "/" + total + " len=" + message.length() + " ";
            if (level == Log.ERROR) {
                Log.e(TAG, prefix + part);
            } else {
                Log.i(TAG, prefix + part);
            }
        }
    }

    private static final class MapSegment {
        private final long start;
        private final long end;
        private final long offset;
        private final String path;

        private MapSegment(long start, long end, long offset, String path) {
            this.start = start;
            this.end = end;
            this.offset = offset;
            this.path = path;
        }
    }

    private static final class LibcoreMemoryReader {
        private final Method peekByteArray;

        private LibcoreMemoryReader(Method peekByteArray) {
            this.peekByteArray = peekByteArray;
        }

        static LibcoreMemoryReader create() {
            try {
                Class<?> memoryClass = Class.forName("libcore.io.Memory");
                Method method = memoryClass.getDeclaredMethod(
                        "peekByteArray",
                        long.class,
                        byte[].class,
                        int.class,
                        int.class
                );
                method.setAccessible(true);
                return new LibcoreMemoryReader(method);
            } catch (Throwable t) {
                return null;
            }
        }

        int read(long address, byte[] buffer, int len) throws Throwable {
            peekByteArray.invoke(null, address, buffer, 0, len);
            return len;
        }

        String name() {
            return "libcore.io.Memory";
        }
    }

    private static final class CipherContext {
        String algorithm;
        int mode;
        String keyHex;
        String keyInfo;
        String ivHex;
        CipherInvocation pendingInvocation;
    }

    private static final class CipherInvocation {
        String methodName;
        byte[] inputBytes;
    }
}
