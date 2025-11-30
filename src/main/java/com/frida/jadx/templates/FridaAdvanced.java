package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 7: Hook Advanced (Hook进阶)
 * Advanced hooking techniques, Frida utilities and memory dumping
 */
public class FridaAdvanced {
    
    private static final String BASE_PATH = "frida-scripts/07-hook-advanced/";
    
    public static final ScriptEntry CLASSLOADER_HELPER = new ScriptEntry(
        "ClassLoader Helper",
        "ClassLoader辅助",
        ScriptLoader.loadScript(BASE_PATH + "01-classloader-helper.js")
    );
    
    public static final ScriptEntry DUMP_CERTIFICATE = new ScriptEntry(
        "Dump Certificate",
        "Dump证书",
        ScriptLoader.loadScript(BASE_PATH + "02-dump-certificate.js")
    );
    
    /**
     * Dump DEX from DexCache (推荐方案)
     * 通过枚举 DexCache 对象脱壳，通用性强，适用于大多数加固壳
     */
    public static final ScriptEntry DUMP_DEX_CACHE = new ScriptEntry(
        "Dump DEX (DexCache)",
        "Dex脱壳 - DexCache枚举方式",
        ScriptLoader.loadScript(BASE_PATH + "03-dump-dex-cache.js")
    );
    
    /**
     * Dump DEX via DefineClass Hook
     * 通过 Hook ClassLinker::DefineClass 捕获类加载，适合分析启动流程
     */
    public static final ScriptEntry DUMP_DEX_DEFINECLASS = new ScriptEntry(
        "Dump DEX (DefineClass)",
        "Dex脱壳 - DefineClass Hook方式",
        ScriptLoader.loadScript(BASE_PATH + "04-dump-dex-defineclass.js")
    );
    
    /**
     * Dump SO libraries from memory
     * 从内存中 Dump Native 库（.so 文件），绕过加固保护
     */
    public static final ScriptEntry DUMP_SO = new ScriptEntry(
        "Dump SO Library",
        "SO库内存Dump",
        ScriptLoader.loadScript(BASE_PATH + "05-dump-so.js")
    );
    
    /**
     * Dump Anonymous Memory
     * Dump匿名内存区域，用于分析动态生成的代码
     */
    public static final ScriptEntry DUMP_ANONYMOUS_MEMORY = new ScriptEntry(
        "Dump Anonymous Memory",
        "Dump匿名内存",
        ScriptLoader.loadScript(BASE_PATH + "06-dump-anonymous-memory.js")
    );
    
    /**
     * Which SO - Find address in module
     * 查找地址所在的 SO 模块，或验证地址是否在预期的 SO 中
     */
    public static final ScriptEntry ADDRESS_IN_WHICH_SO = new ScriptEntry(
        "Which SO (Address Locator)",
        "地址定位 - 查找所属SO",
        ScriptLoader.loadScript(BASE_PATH + "07-address-inWhichSo.js")
    );
    
    /**
     * Hook dlopen
     * 监控动态库加载过程，分析加固、反调试等场景
     */
    public static final ScriptEntry HOOK_DLOPEN = new ScriptEntry(
        "Hook dlopen",
        "Hook SO 加载",
        ScriptLoader.loadScript(BASE_PATH + "08-hook-dlopen.js")
    );
}
