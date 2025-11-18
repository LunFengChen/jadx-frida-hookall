package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 1: Helper Functions
 * Utility functions commonly used in Frida scripts
 */
public class HelperFunctions {
    
    private static final String BASE_PATH = "frida-scripts/helpers/";
    
    public static final ScriptEntry PRINT_STACKTRACE = new ScriptEntry(
        "Print Stack Trace",
        ScriptLoader.loadScript(BASE_PATH + "print-stacktrace.js")
    );
    
    public static final ScriptEntry PRINT_ARGS = new ScriptEntry(
        "Print Arguments",
        ScriptLoader.loadScript(BASE_PATH + "print-args.js")
    );
    
    public static final ScriptEntry BYTES_TO_HEX = new ScriptEntry(
        "Bytes ⇄ Hex Converter",
        ScriptLoader.loadScript(BASE_PATH + "bytes-to-hex.js")
    );
}
