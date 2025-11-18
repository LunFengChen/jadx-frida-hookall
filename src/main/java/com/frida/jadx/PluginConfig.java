package com.frida.jadx;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.prefs.Preferences;

/**
 * Plugin configuration manager using Java Preferences API
 * Stores settings like language preference
 */
public class PluginConfig {
    
    private static final Logger logger = LoggerFactory.getLogger(PluginConfig.class);
    private static final String PREF_KEY_LANGUAGE = "frida_hookall_language";
    private static final String DEFAULT_LANGUAGE = "en"; // "en" or "zh"
    
    private final Preferences prefs;
    private String currentLanguage;
    
    public PluginConfig() {
        prefs = Preferences.userNodeForPackage(PluginConfig.class);
        currentLanguage = prefs.get(PREF_KEY_LANGUAGE, DEFAULT_LANGUAGE);
        logger.info("Loaded language preference: {}", currentLanguage);
    }
    
    /**
     * Get current language setting
     * @return "en" for English, "zh" for Chinese
     */
    public String getLanguage() {
        return currentLanguage;
    }
    
    /**
     * Check if current language is English
     */
    public boolean isEnglish() {
        return "en".equals(currentLanguage);
    }
    
    /**
     * Check if current language is Chinese
     */
    public boolean isChinese() {
        return "zh".equals(currentLanguage);
    }
    
    /**
     * Set language preference
     * @param language "en" for English, "zh" for Chinese
     */
    public void setLanguage(String language) {
        if (!language.equals("en") && !language.equals("zh")) {
            logger.warn("Invalid language: {}, using default", language);
            language = DEFAULT_LANGUAGE;
        }
        
        this.currentLanguage = language;
        prefs.put(PREF_KEY_LANGUAGE, language);
        logger.info("Language preference saved: {}", language);
    }
    
    /**
     * Toggle between English and Chinese
     */
    public void toggleLanguage() {
        String newLanguage = isEnglish() ? "zh" : "en";
        setLanguage(newLanguage);
    }
}
