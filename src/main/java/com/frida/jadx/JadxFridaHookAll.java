package com.frida.jadx;

import jadx.api.plugins.JadxPlugin;
import jadx.api.plugins.JadxPluginContext;
import jadx.api.plugins.JadxPluginInfo;
import jadx.api.plugins.JadxPluginInfoBuilder;
import jadx.gui.ui.MainWindow;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;

/**
 * JADX Frida Hook All Plugin
 * 提供 JDK、Android API 和 JNI Hook 脚本模板
 */
public class JadxFridaHookAll implements JadxPlugin {
    
    private static final Logger logger = LoggerFactory.getLogger(JadxFridaHookAll.class);
    public static final String PLUGIN_ID = "jadx-frida-hookall";
    
    private MainWindow mainWindow;
    private FridaScriptDialog scriptDialog;
    private PluginConfig config;

    @Override
    public void init(JadxPluginContext context) {
        // 检查 GUI 上下文
        if (context.getGuiContext() == null) {
            logger.info("Frida HookAll Plugin: Running in non-GUI mode, plugin features disabled.");
            return;
        }

        try {
            this.mainWindow = (MainWindow) context.getGuiContext().getMainFrame();
            if (this.mainWindow == null) {
                logger.error("Frida HookAll Plugin: Main window is null.");
                return;
            }

            logger.info("Frida HookAll Plugin: Initializing...");
            
            // Initialize configuration
            config = new PluginConfig();
            logger.info("Plugin configuration loaded. Language: {}", config.getLanguage());
            
            // 添加菜单项
            addMenuItems();
            
            logger.info("Frida HookAll Plugin: Initialized successfully.");
            
        } catch (Exception e) {
            logger.error("Frida HookAll Plugin: Initialization error: " + e.getMessage(), e);
        }
    }

    @Override
    public JadxPluginInfo getPluginInfo() {
        return JadxPluginInfoBuilder.pluginId(PLUGIN_ID)
                .name("JADX Frida HookAll")
                .description("Frida Hook script templates for JDK, Android APIs and JNI")
                .homepage("https://github.com/your-repo/jadx-frida-hookall")
                .build();
    }

    /**
     * 添加菜单项和快捷键
     */
    private void addMenuItems() {
        SwingUtilities.invokeLater(() -> {
            try {
                JMenuBar menuBar = mainWindow.getJMenuBar();
                if (menuBar == null) {
                    logger.warn("Frida HookAll Plugin: Menu bar not found");
                    return;
                }

                // 查找或创建 Plugins 菜单
                JMenu pluginsMenu = findOrCreatePluginsMenu(menuBar);

                // 创建 Frida HookAll 菜单项
                JMenuItem fridaMenuItem = new JMenuItem("Frida Hook Templates");
                
                // 添加快捷键 Ctrl+Alt+H (H for Hook)
                fridaMenuItem.setAccelerator(KeyStroke.getKeyStroke(
                        KeyEvent.VK_H, 
                        ActionEvent.CTRL_MASK | ActionEvent.ALT_MASK));
                
                fridaMenuItem.addActionListener(e -> showFridaScriptDialog());
                
                pluginsMenu.add(fridaMenuItem);

                logger.info("Frida HookAll Plugin: Menu item added with shortcut Ctrl+Alt+H");

            } catch (Exception e) {
                logger.error("Frida HookAll Plugin: Error adding menu items: " + e.getMessage(), e);
            }
        });
    }

    /**
     * 查找或创建 Plugins 菜单
     */
    private JMenu findOrCreatePluginsMenu(JMenuBar menuBar) {
        // 查找现有的 Plugins 菜单
        for (int i = 0; i < menuBar.getMenuCount(); i++) {
            JMenu menu = menuBar.getMenu(i);
            if (menu != null && ("Plugins".equals(menu.getText()) || "Plugin".equals(menu.getText()))) {
                return menu;
            }
        }

        // 创建新的 Plugins 菜单
        JMenu pluginsMenu = new JMenu("Plugins");

        // 尝试在 Help 菜单前插入
        boolean inserted = false;
        for (int i = 0; i < menuBar.getMenuCount(); i++) {
            JMenu menu = menuBar.getMenu(i);
            if (menu != null && "Help".equals(menu.getText())) {
                menuBar.add(pluginsMenu, i);
                inserted = true;
                break;
            }
        }

        if (!inserted) {
            menuBar.add(pluginsMenu);
        }

        return pluginsMenu;
    }

    /**
     * 显示 Frida 脚本对话框
     */
    private void showFridaScriptDialog() {
        if (scriptDialog == null) {
            scriptDialog = new FridaScriptDialog(mainWindow, config);
        }
        scriptDialog.setVisible(true);
    }
}
