package com.frida.jadx;

import com.frida.jadx.templates.FridaBasics;
import com.frida.jadx.templates.HelperFunctions;
import com.frida.jadx.templates.HookJDK;
import com.frida.jadx.templates.HookAndroid;
import com.frida.jadx.templates.HookThirdParty;
import com.frida.jadx.templates.HookJNI;
import com.frida.jadx.templates.FridaAdvanced;
import com.frida.jadx.templates.BypassCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.fife.ui.rsyntaxtextarea.*;
import org.fife.ui.rtextarea.*;

import javax.swing.*;
import javax.swing.event.TreeExpansionEvent;
import javax.swing.event.TreeWillExpandListener;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.lang.reflect.Method;

/**
 * Frida script library dialog
 * Displays different categories of Hook scripts in a tree structure
 */
public class FridaScriptDialog extends JDialog {
    
    private static final Logger logger = LoggerFactory.getLogger(FridaScriptDialog.class);
    
    private JTree scriptTree;
    private RSyntaxTextArea scriptTextArea;
    private DefaultMutableTreeNode rootNode;
    private PluginConfig config;
    private jadx.gui.settings.JadxSettings settings;
    private JButton copyButton;
    private JButton copyWithoutCommentsButton;
    private JButton languageButton;
    private JButton closeButton;
    private JButton expandAllButton;
    private JButton collapseAllButton;
    private JButton fontIncreaseButton;
    private JButton fontDecreaseButton;

    public FridaScriptDialog(JFrame parent, PluginConfig config, jadx.gui.settings.JadxSettings settings) {
        super(parent, "Frida实用脚本库", false);
        this.config = config;
        this.settings = settings;
        initUI();
        loadScriptTemplates();
        updateLanguage(); // Apply language settings
        
        setSize(900, 600);
        setLocationRelativeTo(parent);
    }

    /**
     * Initialize UI components
     */
    private void initUI() {
        setLayout(new BorderLayout(10, 10));

        // Create tree structure
        rootNode = new DefaultMutableTreeNode("Frida实用脚本库");
        scriptTree = new JTree(rootNode);
        scriptTree.setRootVisible(true);
        
        // Set tree selection listener - single click to view script
        scriptTree.addTreeSelectionListener(e -> {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) scriptTree.getLastSelectedPathComponent();
            if (node != null && node.getUserObject() instanceof ScriptTemplate) {
                displayScript((ScriptTemplate) node.getUserObject());
            }
        });
        
        // Add accordion style expansion (single expand)
        scriptTree.addTreeWillExpandListener(new TreeWillExpandListener() {
            @Override
            public void treeWillExpand(TreeExpansionEvent event) throws ExpandVetoException {
                TreePath path = event.getPath();
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
                
                // Only apply to first level nodes (categories)
                if (node.getParent() == rootNode) {
                    collapseOtherNodes(node);
                }
            }

            @Override
            public void treeWillCollapse(TreeExpansionEvent event) throws ExpandVetoException {
                // Do nothing
            }
        });

        JScrollPane treeScrollPane = new JScrollPane(scriptTree);
        treeScrollPane.setPreferredSize(new Dimension(300, 0));

        // Create script display area using RSyntaxTextArea
        scriptTextArea = new RSyntaxTextArea();
        scriptTextArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
        scriptTextArea.setCodeFoldingEnabled(true);
        scriptTextArea.setAntiAliasingEnabled(true);
        scriptTextArea.setEditable(false);
        
        // Apply Theme based on JADX settings (via Reflection to avoid compilation errors)
        try {
            String themePath = null;
            try {
                // Try to get editor theme path via reflection
                Method getEditorThemePath = settings.getClass().getMethod("getEditorThemePath");
                themePath = (String) getEditorThemePath.invoke(settings);
            } catch (Exception e) {
                logger.debug("Could not get editor theme path via reflection", e);
            }

            boolean isDark = true; // Default to dark
            if (themePath != null) {
                isDark = themePath.toLowerCase().contains("dark") || themePath.toLowerCase().contains("darcula");
            }
            
            String themeResource = isDark ? "/org/fife/ui/rsyntaxtextarea/themes/dark.xml" 
                                          : "/org/fife/ui/rsyntaxtextarea/themes/default.xml";
            
            Theme theme = Theme.load(getClass().getResourceAsStream(themeResource));
            theme.apply(scriptTextArea);
        } catch (Exception e) {
            logger.warn("Failed to apply theme to RSyntaxTextArea", e);
        }

        // Set font from JADX settings
        Font font = settings.getFont();
        if (font == null) {
            font = new Font("Consolas", Font.PLAIN, 13);
        }
        
        // Check if JADX font supports Chinese, if not, fallback to a font that does
        if (!isChineseSupported(font)) {
             // Try Microsoft YaHei UI first
             Font chineseFont = new Font("Microsoft YaHei UI", Font.PLAIN, font.getSize());
             if (isChineseSupported(chineseFont)) {
                 font = chineseFont;
             } else {
                 // Fallback to SimHei
                 chineseFont = new Font("SimHei", Font.PLAIN, font.getSize());
                 if (isChineseSupported(chineseFont)) {
                    font = chineseFont;
                 }
             }
        }
        scriptTextArea.setFont(font);
        
        scriptTextArea.setText("Click tree node to view Frida script template");

        RTextScrollPane textScrollPane = new RTextScrollPane(scriptTextArea);
        textScrollPane.setFoldIndicatorEnabled(true);

        // Create operation button panel
        JPanel buttonPanel = new JPanel(new BorderLayout());
        
        // Left side buttons (Language, Expand/Collapse, Font Size)
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        languageButton = new JButton();
        languageButton.addActionListener(e -> toggleLanguage());
        leftPanel.add(languageButton);
        
        expandAllButton = new JButton();
        expandAllButton.addActionListener(e -> expandAllNodes());
        leftPanel.add(expandAllButton);
        
        collapseAllButton = new JButton();
        collapseAllButton.addActionListener(e -> collapseAllNodes());
        leftPanel.add(collapseAllButton);

        // Font size buttons
        fontIncreaseButton = new JButton("A+");
        fontIncreaseButton.setMargin(new Insets(2, 5, 2, 5));
        fontIncreaseButton.addActionListener(e -> modifyFontSize(2.0f));
        leftPanel.add(fontIncreaseButton);

        fontDecreaseButton = new JButton("A-");
        fontDecreaseButton.setMargin(new Insets(2, 5, 2, 5));
        fontDecreaseButton.addActionListener(e -> modifyFontSize(-2.0f));
        leftPanel.add(fontDecreaseButton);
        
        // Copy and Close buttons (right side)
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        copyButton = new JButton();
        copyButton.addActionListener(e -> copyScriptToClipboard(false));
        copyWithoutCommentsButton = new JButton();
        copyWithoutCommentsButton.addActionListener(e -> copyScriptToClipboard(true));
        closeButton = new JButton();
        closeButton.addActionListener(e -> setVisible(false));
        rightPanel.add(copyButton);
        rightPanel.add(copyWithoutCommentsButton);
        rightPanel.add(closeButton);
        
        buttonPanel.add(leftPanel, BorderLayout.WEST);
        buttonPanel.add(rightPanel, BorderLayout.EAST);

        // Create split pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScrollPane, textScrollPane);
        splitPane.setDividerLocation(300);

        // Add components
        add(splitPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private boolean isChineseSupported(Font font) {
        return font.canDisplay('中');
    }

    /**
     * Load script templates (9 categories)
     */
    private void loadScriptTemplates() {
        logger.info("Loading Frida script templates...");
        boolean isEnglish = config.isEnglish();
        
        // Category 1: Frida APIs
        String basicsTitle = isEnglish ? "1. Frida APIs" : "1. Frida API";
        DefaultMutableTreeNode basicsNode = new DefaultMutableTreeNode(basicsTitle);
        basicsNode.add(createScriptNode(FridaBasics.HOOK_BASIC, 0));
        basicsNode.add(createScriptNode(FridaBasics.HOOK_OVERLOAD, 1));
        basicsNode.add(createScriptNode(FridaBasics.HOOK_CONSTRUCTOR, 2));
        basicsNode.add(createScriptNode(FridaBasics.HOOK_FIELD, 3));
        basicsNode.add(createScriptNode(FridaBasics.HOOK_INNER_CLASS, 4));
        basicsNode.add(createScriptNode(FridaBasics.ENUMERATE_CLASSES, 5));
        basicsNode.add(createScriptNode(FridaBasics.RPC_CALL_METHOD, 6));
        rootNode.add(basicsNode);
        logger.debug("Loaded {} Frida Basics scripts", basicsNode.getChildCount());
        
        // Category 2: Helper Functions
        String helperTitle = isEnglish ? "2. Helper Functions" : "2. 辅助函数";
        DefaultMutableTreeNode helperNode = new DefaultMutableTreeNode(helperTitle);
        helperNode.add(createScriptNode(HelperFunctions.PRINT_CALLSTACK, 0));
        helperNode.add(createScriptNode(HelperFunctions.DATA_CONVERT, 1));
        helperNode.add(createScriptNode(HelperFunctions.PRINT_ARGS, 2));
        helperNode.add(createScriptNode(HelperFunctions.PRINT_MAP, 3));
        helperNode.add(createScriptNode(HelperFunctions.PRINT_STRING_ARRAY, 4));
        helperNode.add(createScriptNode(HelperFunctions.PRINT_METHOD_SIGNATURE, 5));
        helperNode.add(createScriptNode(HelperFunctions.PRINT_CUSTOM_OBJECT, 6));
        helperNode.add(createScriptNode(HelperFunctions.PRINT_OBJECT_ARRAY, 7));
        rootNode.add(helperNode);
        logger.debug("Loaded {} Helper Functions scripts", helperNode.getChildCount());

        // Category 3: Hook JDK
        String jdkTitle = isEnglish ? "3. Hook JDK" : "3. Hook JDK";
        DefaultMutableTreeNode jdkNode = new DefaultMutableTreeNode(jdkTitle);
        jdkNode.add(createScriptNode(HookJDK.MONITOR_STRING, 0));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_STRINGBUILDER, 1));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_BASE64_JAVA, 2));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_URL, 3));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_FILE, 4));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_ALL_MAP, 5));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_ARRAYLIST, 6));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_COLLECTIONS, 7));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_JSON, 8));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_CRYPTO, 9));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_PROCESS, 10));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_SYSTEM_LOAD, 11));
        jdkNode.add(createScriptNode(HookJDK.MONITOR_THREAD, 12));
        rootNode.add(jdkNode);
        logger.debug("Loaded {} Hook JDK scripts", jdkNode.getChildCount());

        // Category 4: Hook Android
        String androidTitle = isEnglish ? "4. Hook Android" : "4. Hook Android";
        DefaultMutableTreeNode androidNode = new DefaultMutableTreeNode(androidTitle);
        androidNode.add(createScriptNode(HookAndroid.MONITOR_BASE64_ANDROID, 0));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_ACTIVITY, 1));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_DIALOG, 2));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_STRINGFACTORY, 3));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_TOAST, 4));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_EDITTEXT, 5));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_WEBVIEW, 6));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_LOG, 7));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_TEXTUTILS, 8));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_SHAREDPREFERENCES, 9));
        androidNode.add(createScriptNode(HookAndroid.BLOCK_POPUP, 10));
        androidNode.add(createScriptNode(HookAndroid.MONITOR_CRASH, 11));
        rootNode.add(androidNode);
        logger.debug("Loaded {} Hook Android scripts", androidNode.getChildCount());

        // Category 5: Hook Third-Party
        String thirdPartyTitle = isEnglish ? "5. Hook Third-Party" : "5. Hook第三方库";
        DefaultMutableTreeNode thirdPartyNode = new DefaultMutableTreeNode(thirdPartyTitle);
        thirdPartyNode.add(createScriptNode(HookThirdParty.MONITOR_OKHTTP, 0));
        thirdPartyNode.add(createScriptNode(HookThirdParty.MONITOR_OKHTTP3, 1));
        thirdPartyNode.add(createScriptNode(HookThirdParty.MONITOR_JSONOBJECT, 2));
        rootNode.add(thirdPartyNode);
        logger.debug("Loaded {} Hook Third-Party scripts", thirdPartyNode.getChildCount());

        // Category 6: Hook JNI
        String jniTitle = isEnglish ? "6. Hook JNI" : "6. JNI相关";
        DefaultMutableTreeNode jniNode = new DefaultMutableTreeNode(jniTitle);
        jniNode.add(createScriptNode(HookJNI.HOOK_REGISTER_NATIVES, 0));
        jniNode.add(createScriptNode(HookJNI.JNITRACE_USAGE, 1));
        rootNode.add(jniNode);
        logger.debug("Loaded {} Hook JNI scripts", jniNode.getChildCount());
        
        // Category 7: Hook Advanced
        String advancedTitle = isEnglish ? "7. Hook Advanced" : "7. Hook进阶";
        DefaultMutableTreeNode advancedNode = new DefaultMutableTreeNode(advancedTitle);
        advancedNode.add(createScriptNode(FridaAdvanced.CLASSLOADER_HELPER, 0));
        advancedNode.add(createScriptNode(FridaAdvanced.DUMP_CERTIFICATE, 1));
        advancedNode.add(createScriptNode(FridaAdvanced.DUMP_DEX_CACHE, 2));
        advancedNode.add(createScriptNode(FridaAdvanced.DUMP_DEX_DEFINECLASS, 3));
        advancedNode.add(createScriptNode(FridaAdvanced.DUMP_SO, 4));
        advancedNode.add(createScriptNode(FridaAdvanced.DUMP_ANONYMOUS_MEMORY, 5));
        advancedNode.add(createScriptNode(FridaAdvanced.ADDRESS_IN_WHICH_SO, 6));
        advancedNode.add(createScriptNode(FridaAdvanced.HOOK_DLOPEN, 7));
        rootNode.add(advancedNode);
        logger.debug("Loaded {} Hook Advanced scripts", advancedNode.getChildCount());
        
        // Category 8: Bypass Check
        String bypassTitle = isEnglish ? "8. Bypass Check" : "8. 绕过检测";
        DefaultMutableTreeNode bypassNode = new DefaultMutableTreeNode(bypassTitle);
        bypassNode.add(createScriptNode(BypassCheck.BYPASS_ROOT_DETECTION, 0));
        bypassNode.add(createScriptNode(BypassCheck.BYPASS_SSL_PINNING, 1));
        bypassNode.add(createScriptNode(BypassCheck.BYPASS_MSA_FRIDA_CHECK, 2));
        rootNode.add(bypassNode);
        logger.debug("Loaded {} Bypass Check scripts", bypassNode.getChildCount());

        // Refresh tree
        DefaultTreeModel model = (DefaultTreeModel) scriptTree.getModel();
        model.reload();
        
        // Default: Expand only the root node (implicitly done by JTree usually, but we can ensure)
        // Do NOT expand all nodes.
        
        logger.info("Script templates loaded successfully. Total categories: 8");
    }

    /**
     * Create script node from ScriptEntry with index
     */
    private DefaultMutableTreeNode createScriptNode(FridaTemplates.ScriptEntry entry, int index) {
        boolean isEnglish = config.isEnglish();
        String displayName = (index + 1) + ". " + entry.getName(isEnglish);
        ScriptTemplate template = new ScriptTemplate(displayName, entry.code);
        return new DefaultMutableTreeNode(template);
    }

    /**
     * display Script Code
     */
    private void displayScript(ScriptTemplate template) {
        scriptTextArea.setText(template.getScript());
        scriptTextArea.setCaretPosition(0); // Scroll to top
    }

    /**
     * Copy script to clipboard
     * @param removeComments true to remove comments, false to keep them
     */
    private void copyScriptToClipboard(boolean removeComments) {
        String script = scriptTextArea.getText();
        if (script != null && !script.isEmpty()) {
            if (removeComments) {
                script = removeComments(script);
            }
            StringSelection selection = new StringSelection(script);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
            
            String message = config.isEnglish() ? 
                (removeComments ? "Script copied to clipboard (no comments)!" : "Script copied to clipboard!") :
                (removeComments ? "脚本已复制到剪贴板（无注释）！" : "脚本已复制到剪贴板！");
            String title = config.isEnglish() ? "Success" : "成功";
            JOptionPane.showMessageDialog(this, message, title, JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    /**
     * Remove comments from JavaScript code (supports single-line and multi-line comments)
     * @param code JavaScript code
     * @return Code without comments
     */
    private String removeComments(String code) {
        StringBuilder result = new StringBuilder();
        boolean inMultiLineComment = false;
        boolean inString = false;
        char stringChar = '\0';
        
        for (int i = 0; i < code.length(); i++) {
            char c = code.charAt(i);
            char next = (i + 1 < code.length()) ? code.charAt(i + 1) : '\0';
            
            // Handle string boundaries
            if (!inMultiLineComment && (c == '"' || c == '\'' || c == '`')) {
                if (!inString) {
                    inString = true;
                    stringChar = c;
                    result.append(c);
                } else if (c == stringChar && (i == 0 || code.charAt(i - 1) != '\\')) {
                    inString = false;
                    stringChar = '\0';
                    result.append(c);
                } else {
                    result.append(c);
                }
                continue;
            }
            
            // If in string, just append
            if (inString) {
                result.append(c);
                continue;
            }
            
            // Handle multi-line comment start
            if (!inMultiLineComment && c == '/' && next == '*') {
                inMultiLineComment = true;
                i++; // Skip next char
                continue;
            }
            
            // Handle multi-line comment end
            if (inMultiLineComment && c == '*' && next == '/') {
                inMultiLineComment = false;
                i++; // Skip next char
                continue;
            }
            
            // Handle single-line comment
            if (!inMultiLineComment && c == '/' && next == '/') {
                // Skip until end of line
                while (i < code.length() && code.charAt(i) != '\n') {
                    i++;
                }
                if (i < code.length()) {
                    result.append('\n'); // Keep the newline
                }
                continue;
            }
            
            // If in multi-line comment, skip
            if (inMultiLineComment) {
                continue;
            }
            
            // Otherwise, append the character
            result.append(c);
        }
        
        // Remove empty lines
        StringBuilder finalResult = new StringBuilder();
        String[] lines = result.toString().split("\n");
        for (String line : lines) {
            if (!line.trim().isEmpty()) {
                finalResult.append(line).append("\n");
            }
        }
        
        return finalResult.toString();
    }
    
    /**
     * Count occurrences of a character in a string
     */
    private int countOccurrences(String str, char ch) {
        int count = 0;
        for (char c : str.toCharArray()) {
            if (c == ch) count++;
        }
        return count;
    }
    
    /**
     * Modify font size
     */
    private void modifyFontSize(float delta) {
        Font font = scriptTextArea.getFont();
        float newSize = font.getSize() + delta;
        if (newSize >= 8 && newSize <= 72) {
            scriptTextArea.setFont(font.deriveFont(newSize));
        }
    }

    /**
     * Toggle language between English and Chinese
     */
    private void toggleLanguage() {
        config.toggleLanguage();
        updateLanguage();
        
        // Reload script templates to refresh category names
        rootNode.removeAllChildren();
        loadScriptTemplates();
        
        String message = config.isEnglish() ? 
            "Language switched to English. Dialog will refresh." : 
            "已切换到中文。对话框将刷新。";
        String title = config.isEnglish() ? "Language Changed" : "语言已更改";
        JOptionPane.showMessageDialog(this, message, title, JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * Update all UI text based on current language setting
     */
    private void updateLanguage() {
        boolean isEnglish = config.isEnglish();
        
        // Update dialog title
        setTitle(isEnglish ? "Frida Script Library" : "Frida实用脚本库");
        
        // Update root node text
        rootNode.setUserObject(isEnglish ? "Frida Script Library" : "Frida实用脚本库");
        
        // Update buttons
        languageButton.setText(isEnglish ? "中文" : "English");
        languageButton.setToolTipText(isEnglish ? "Switch to Chinese" : "切换到英文");
        expandAllButton.setText(isEnglish ? "Expand All" : "展开全部");
        expandAllButton.setToolTipText(isEnglish ? "Expand all tree nodes" : "展开所有树节点");
        collapseAllButton.setText(isEnglish ? "Collapse All" : "折叠全部");
        collapseAllButton.setToolTipText(isEnglish ? "Collapse all tree nodes" : "折叠所有树节点");
        
        fontIncreaseButton.setToolTipText(isEnglish ? "Increase Font Size" : "放大字体");
        fontDecreaseButton.setToolTipText(isEnglish ? "Decrease Font Size" : "缩小字体");
        
        copyButton.setText(isEnglish ? "Copy Script" : "复制脚本");
        copyWithoutCommentsButton.setText(isEnglish ? "Copy (No Comments)" : "复制(无注释)");
        copyWithoutCommentsButton.setToolTipText(isEnglish ? "Copy script without comments" : "复制脚本不包含注释");
        closeButton.setText(isEnglish ? "Close" : "关闭");
        
        // Update placeholder text
        if (scriptTextArea.getText().contains("Click tree node") || 
            scriptTextArea.getText().contains("点击树节点")) {
            scriptTextArea.setText(isEnglish ? 
                "Click tree node to view Frida script library" : 
                "点击树节点查看Frida实用脚本库");
        }
        
        logger.info("UI language updated to: {}", isEnglish ? "English" : "Chinese");
    }

    /**
     * Collapse other nodes at the same level
     */
    private void collapseOtherNodes(DefaultMutableTreeNode node) {
        TreeNode parent = node.getParent();
        if (parent == null) return;
        
        for (int i = 0; i < parent.getChildCount(); i++) {
            TreeNode child = parent.getChildAt(i);
            if (child != node) {
                TreePath path = new TreePath(((DefaultMutableTreeNode)child).getPath());
                if (scriptTree.isExpanded(path)) {
                    scriptTree.collapsePath(path);
                }
            }
        }
    }

    /**
     * Expand all tree nodes (called by button)
     */
    private void expandAllNodes() {
        expandAllNodes(scriptTree, 0, scriptTree.getRowCount());
        logger.debug("All tree nodes expanded");
    }
    
    /**
     * Collapse all tree nodes (called by button)
     */
    private void collapseAllNodes() {
        int row = scriptTree.getRowCount() - 1;
        while (row >= 1) { // Keep root expanded
            scriptTree.collapseRow(row);
            row--;
        }
        logger.debug("All tree nodes collapsed");
    }
    
    /**
     * 展开所有树节点（递归辅助方法）
     */
    private void expandAllNodes(JTree tree, int startingIndex, int rowCount) {
        for (int i = startingIndex; i < rowCount; ++i) {
            tree.expandRow(i);
        }

        if (tree.getRowCount() != rowCount) {
            expandAllNodes(tree, rowCount, tree.getRowCount());
        }
    }

    /**
     * 脚本数据类
     */
    static class ScriptTemplate {
        private final String name;
        private final String script;

        public ScriptTemplate(String name, String script) {
            this.name = name;
            this.script = script;
        }

        public String getName() {
            return name;
        }

        public String getScript() {
            return script;
        }

        @Override
        public String toString() {
            return name;
        }
    }
}
