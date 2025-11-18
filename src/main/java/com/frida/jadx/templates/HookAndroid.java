package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 3: Hook Android APIs
 * Scripts for hooking Android framework APIs
 */
public class HookAndroid {
    
    private static final String BASE_PATH = "frida-scripts/hook-android/";
    
    public static final ScriptEntry MONITOR_DIALOG = new ScriptEntry(
        "Monitor Dialog",
        ScriptLoader.loadScript(BASE_PATH + "monitor-dialog.js")
    );
    
    // TODO: Add more scripts here
    // Example:
    // public static final ScriptEntry MONITOR_TOAST = new ScriptEntry(
    //     "Monitor Toast",
    //     ScriptLoader.loadScript(BASE_PATH + "monitor-toast.js")
    // );
}
