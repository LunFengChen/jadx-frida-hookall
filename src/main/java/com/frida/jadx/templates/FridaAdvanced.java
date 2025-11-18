package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 4: Frida Advanced APIs
 * Advanced Frida features like JNI hooks, native hooks, etc.
 */
public class FridaAdvanced {
    
    private static final String BASE_PATH = "frida-scripts/frida-advanced/";
    
    public static final ScriptEntry JNI_REGISTER_NATIVES = new ScriptEntry(
        "Monitor JNI RegisterNatives",
        ScriptLoader.loadScript(BASE_PATH + "jni-register-natives.js")
    );
    
    // TODO: Add more scripts here
    // Example:
    // public static final ScriptEntry ENUM_MODULES = new ScriptEntry(
    //     "Enumerate Modules",
    //     ScriptLoader.loadScript(BASE_PATH + "enumerate-modules.js")
    // );
}
