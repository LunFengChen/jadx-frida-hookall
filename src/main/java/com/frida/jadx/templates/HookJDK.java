package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 2: Hook JDK APIs
 * Scripts for hooking Java standard library APIs
 */
public class HookJDK {
    
    private static final String BASE_PATH = "frida-scripts/hook-jdk/";
    
    public static final ScriptEntry PRINT_MAP = new ScriptEntry(
        "Print Map Content",
        ScriptLoader.loadScript(BASE_PATH + "print-map.js")
    );
    
    // TODO: Add more scripts here
    // Example:
    // public static final ScriptEntry PRINT_LIST = new ScriptEntry(
    //     "Print List Content",
    //     ScriptLoader.loadScript(BASE_PATH + "print-list.js")
    // );
}
