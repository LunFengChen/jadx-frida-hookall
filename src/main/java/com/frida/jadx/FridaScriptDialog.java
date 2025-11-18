package com.frida.jadx;

import com.frida.jadx.templates.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;

/**
 * Frida 脚本模板对话框
 * 使用树形结构展示不同类别的 Hook 脚本
 */
public class FridaScriptDialog extends JDialog {
    
    private static final Logger logger = LoggerFactory.getLogger(FridaScriptDialog.class);
    
    private JTree scriptTree;
    private JTextArea scriptTextArea;
    private DefaultMutableTreeNode rootNode;
    private PluginConfig config;
    private JButton copyButton;
    private JButton languageButton;
    private JButton closeButton;
    private JButton expandAllButton;
    private JButton collapseAllButton;

    public FridaScriptDialog(JFrame parent, PluginConfig config) {
        super(parent, "Frida Hook Script Templates", false);
        this.config = config;
        initUI();
        loadScriptTemplates();
        updateLanguage(); // Apply language settings
        
        setSize(900, 600);
        setLocationRelativeTo(parent);
    }

    /**
     * 初始化 UI 组件
     */
    private void initUI() {
        setLayout(new BorderLayout(10, 10));

        // 创建树形结构
        rootNode = new DefaultMutableTreeNode("Frida Hook Templates");
        scriptTree = new JTree(rootNode);
        scriptTree.setRootVisible(true);
        
        // 设置树形选择监听 - 单击即可查看脚本
        scriptTree.addTreeSelectionListener(e -> {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) scriptTree.getLastSelectedPathComponent();
            if (node != null && node.getUserObject() instanceof ScriptTemplate) {
                displayScript((ScriptTemplate) node.getUserObject());
            }
        });

        JScrollPane treeScrollPane = new JScrollPane(scriptTree);
        treeScrollPane.setPreferredSize(new Dimension(300, 0));

        // 创建脚本显示区域
        scriptTextArea = new JTextArea();
        scriptTextArea.setEditable(false);
        
        // 设置字体，支持中文显示
        Font font = new Font("Microsoft YaHei UI", Font.PLAIN, 13);
        if (font.getFamily().equals("Dialog")) {
            // 如果微软雅黑不可用，使用默认等宽字体
            font = new Font("Monospaced", Font.PLAIN, 12);
        }
        scriptTextArea.setFont(font);
        scriptTextArea.setTabSize(4);
        scriptTextArea.setText("Click tree node to view Frida script template");

        JScrollPane textScrollPane = new JScrollPane(scriptTextArea);

        // 创建操作按钮面板
        JPanel buttonPanel = new JPanel(new BorderLayout());
        
        // Left side buttons (Language, Expand/Collapse)
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
        
        // Copy and Close buttons (right side)
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        copyButton = new JButton();
        copyButton.addActionListener(e -> copyScriptToClipboard());
        closeButton = new JButton();
        closeButton.addActionListener(e -> setVisible(false));
        rightPanel.add(copyButton);
        rightPanel.add(closeButton);
        
        buttonPanel.add(leftPanel, BorderLayout.WEST);
        buttonPanel.add(rightPanel, BorderLayout.EAST);

        // 创建分割面板
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScrollPane, textScrollPane);
        splitPane.setDividerLocation(300);

        // 添加组件
        add(splitPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    /**
     * Load script templates (4 categories)
     */
    private void loadScriptTemplates() {
        logger.info("Loading Frida script templates...");
        boolean isEnglish = config.isEnglish();
        
        // Category 1: Helper Functions (辅助函数)
        String helperTitle = isEnglish ? "1. Helper Functions" : "1. 辅助函数";
        DefaultMutableTreeNode helperNode = new DefaultMutableTreeNode(helperTitle);
        helperNode.add(createScriptNode(HelperFunctions.PRINT_STACKTRACE));
        helperNode.add(createScriptNode(HelperFunctions.PRINT_ARGS));
        helperNode.add(createScriptNode(HelperFunctions.BYTES_TO_HEX));
        rootNode.add(helperNode);
        logger.debug("Loaded {} Helper Functions scripts", helperNode.getChildCount());

        // Category 2: Hook JDK
        String jdkTitle = isEnglish ? "2. Hook JDK" : "2. Hook JDK";
        DefaultMutableTreeNode jdkNode = new DefaultMutableTreeNode(jdkTitle);
        jdkNode.add(createScriptNode(HookJDK.PRINT_MAP));
        rootNode.add(jdkNode);
        logger.debug("Loaded {} Hook JDK scripts", jdkNode.getChildCount());

        // Category 3: Hook Android
        String androidTitle = isEnglish ? "3. Hook Android" : "3. Hook Android";
        DefaultMutableTreeNode androidNode = new DefaultMutableTreeNode(androidTitle);
        androidNode.add(createScriptNode(HookAndroid.MONITOR_DIALOG));
        rootNode.add(androidNode);
        logger.debug("Loaded {} Hook Android scripts", androidNode.getChildCount());

        // Category 4: Frida Advanced
        String fridaTitle = isEnglish ? "4. Frida Advanced" : "4. Frida 进阶";
        DefaultMutableTreeNode fridaNode = new DefaultMutableTreeNode(fridaTitle);
        fridaNode.add(createScriptNode(FridaAdvanced.JNI_REGISTER_NATIVES));
        rootNode.add(fridaNode);
        logger.debug("Loaded {} Frida Advanced scripts", fridaNode.getChildCount());

        // Refresh tree
        DefaultTreeModel model = (DefaultTreeModel) scriptTree.getModel();
        model.reload();
        
        // Expand all nodes by default
        expandAllNodes(scriptTree, 0, scriptTree.getRowCount());
        
        logger.info("Script templates loaded successfully. Total categories: 4");
    }

    /**
     * Create script node from ScriptEntry
     */
    private DefaultMutableTreeNode createScriptNode(FridaTemplates.ScriptEntry entry) {
        ScriptTemplate template = new ScriptTemplate(entry.name, entry.code);
        return new DefaultMutableTreeNode(template);
    }

    /**
     * 显示脚本内容
     */
    private void displayScript(ScriptTemplate template) {
        scriptTextArea.setText(template.getScript());
        scriptTextArea.setCaretPosition(0); // 滚动到顶部
    }

    /**
     * Copy script to clipboard
     */
    private void copyScriptToClipboard() {
        String script = scriptTextArea.getText();
        if (script != null && !script.isEmpty()) {
            StringSelection selection = new StringSelection(script);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
            
            String message = config.isEnglish() ? 
                "Script copied to clipboard!" : "脚本已复制到剪贴板！";
            String title = config.isEnglish() ? "Success" : "成功";
            JOptionPane.showMessageDialog(this, message, title, JOptionPane.INFORMATION_MESSAGE);
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
        setTitle(isEnglish ? "Frida Hook Script Templates" : "Frida Hook 脚本模板");
        
        // Update root node text
        rootNode.setUserObject(isEnglish ? "Frida Hook Templates" : "Frida Hook 模板");
        
        // Update buttons
        languageButton.setText(isEnglish ? "中文" : "English");
        languageButton.setToolTipText(isEnglish ? "Switch to Chinese" : "切换到英文");
        expandAllButton.setText(isEnglish ? "Expand All" : "展开全部");
        expandAllButton.setToolTipText(isEnglish ? "Expand all tree nodes" : "展开所有树节点");
        collapseAllButton.setText(isEnglish ? "Collapse All" : "折叠全部");
        collapseAllButton.setToolTipText(isEnglish ? "Collapse all tree nodes" : "折叠所有树节点");
        copyButton.setText(isEnglish ? "Copy Script" : "复制脚本");
        closeButton.setText(isEnglish ? "Close" : "关闭");
        
        // Update placeholder text
        if (scriptTextArea.getText().contains("Click tree node") || 
            scriptTextArea.getText().contains("点击树节点")) {
            scriptTextArea.setText(isEnglish ? 
                "Click tree node to view Frida script template" : 
                "点击树节点查看 Frida 脚本模板");
        }
        
        logger.info("UI language updated to: {}", isEnglish ? "English" : "Chinese");
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
     * 脚本模板数据类
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
