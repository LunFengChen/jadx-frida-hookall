package com.frida.jadx;

/**
 * Frida Hook Script Template Library
 * 
 * This is the main entry point that organizes scripts into 4 categories:
 * 1. Helper Functions  - Utility functions
 * 2. Hook JDK - Java standard library hooks
 * 3. Hook Android - Android framework hooks
 * 4. Frida Advanced - Advanced Frida features (JNI, Native, etc.)
 * 
 * Scripts are loaded from .js files in resources/frida-scripts/
 */
public class FridaTemplates {
    
    /**
     * Script template entry containing name and code
     */
    public static class ScriptEntry {
        public final String name;
        public final String code;
        
        public ScriptEntry(String name, String code) {
            this.name = name;
            this.code = code;
        }
    }
}
