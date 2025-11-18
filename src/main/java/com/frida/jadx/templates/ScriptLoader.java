package com.frida.jadx.templates;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

/**
 * Utility class to load Frida scripts from resources
 */
public class ScriptLoader {
    
    private static final Logger logger = LoggerFactory.getLogger(ScriptLoader.class);
    
    /**
     * Load script content from resource path
     * @param resourcePath Path to the .js file in resources (e.g., "frida-scripts/helpers/print-stacktrace.js")
     * @return Script content as String
     */
    public static String loadScript(String resourcePath) {
        try {
            logger.debug("Loading script from: {}", resourcePath);
            
            InputStream inputStream = ScriptLoader.class.getClassLoader().getResourceAsStream(resourcePath);
            if (inputStream == null) {
                logger.error("Script file not found: {}", resourcePath);
                return "// Script not found: " + resourcePath;
            }
            
            String content = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))
                    .lines()
                    .collect(Collectors.joining("\n"));
            
            logger.debug("Script loaded successfully: {} ({} chars)", resourcePath, content.length());
            return content;
            
        } catch (Exception e) {
            logger.error("Error loading script: " + resourcePath, e);
            return "// Error loading script: " + e.getMessage();
        }
    }
}
