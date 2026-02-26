package com.byd.xposedhooks;

import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class BydHookInit implements IXposedHookLoadPackage {
    private static final String TAG = "BYD-Xposed";
    private static final String OVERSEAS_PACKAGE = "com.byd.bydautolink";
    private static final String CHINESE_PACKAGE = "com.byd.aeri.caranywhere";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!OVERSEAS_PACKAGE.equals(lpparam.packageName) && !CHINESE_PACKAGE.equals(lpparam.packageName)) {
            return;
        }
        Log.i(TAG, "Initialising CryptoTool hooks for " + lpparam.packageName);
        CryptoToolHook.install(lpparam.classLoader);
    }
}
