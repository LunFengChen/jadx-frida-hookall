package com.frida.jadx.templates;

import com.frida.jadx.FridaTemplates.ScriptEntry;

/**
 * Category 8: Bypass Check (绕过检测)
 * Scripts for bypassing various security checks and detections
 */
public class BypassCheck {
    
    private static final String BASE_PATH = "frida-scripts/08-bypass-check/";
    
    /**
     * Bypass Root Detection (Universal)
     * 通用Root检测绕过，Hook常见的文件检测和命令执行
     */
    public static final ScriptEntry BYPASS_ROOT_DETECTION = new ScriptEntry(
        "Bypass Root Detection",
        "绕过Root检测",
        ScriptLoader.loadScript(BASE_PATH + "01-bypass-root-detection.js")
    );
    
    /**
     * Bypass SSL Pinning (Universal)
     * 通用SSL证书校验绕过，支持系统TrustManager和OkHttp CertificatePinner
     */
    public static final ScriptEntry BYPASS_SSL_PINNING = new ScriptEntry(
        "Bypass SSL Pinning",
        "绕过SSL证书校验",
        ScriptLoader.loadScript(BASE_PATH + "02-bypass-ssl-pinning.js")
    );
    
    /**
     * Bypass MSA Frida Detection
     * 绕过移动安全联盟(MSA)的Frida检测，通过Hook入口函数
     */
    public static final ScriptEntry BYPASS_MSA_FRIDA_CHECK = new ScriptEntry(
        "Bypass MSA Frida Check",
        "绕过MSA Frida检测",
        ScriptLoader.loadScript(BASE_PATH + "03-bypass-msa-frida-check.js")
    );

    public static final ScriptEntry BYPASS_FLUTTER_TLS = new ScriptEntry(
        "Bypass Flutter TLS",
        "绕过Flutter TLS校验",
        ScriptLoader.loadScript(BASE_PATH + "06-bypass-flutter-tls.js")
    );
}
