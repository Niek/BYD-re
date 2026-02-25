package com.byd.xposedhooks;

import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class BydHookInit implements IXposedHookLoadPackage {
    private static final String TAG = "BYD-Xposed";
    private static final String TARGET_PACKAGE = "com.byd.bydautolink"; // Overseas app
    //private static final String TARGET_PACKAGE = "com.byd.aeri.caranywhere"; // Chinese app

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!TARGET_PACKAGE.equals(lpparam.packageName)) {
            return;
        }
        Log.i(TAG, "Initialising CryptoTool hooks for " + TARGET_PACKAGE);
        CryptoToolHook.install(lpparam.classLoader);
    }
}
