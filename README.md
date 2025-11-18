# JADX Frida HookAll Plugin

一个 JADX 插件，提供丰富的 Frida Hook 脚本模板，用于快速进行 Android 逆向分析和动态调试。

## 功能特性

### 📦 三大类脚本模板

1. **JDK API Hooks**
   - 打印堆栈跟踪
   - 打印 Map 集合内容
   - 打印 List 集合内容
   - Hook String 操作
   - Hook 文件 I/O 操作

2. **Android API Hooks**
   - 监控 Dialog 显示
   - 监控 Toast 消息
   - 监控 Activity 生命周期
   - 监控网络请求（OkHttp/HttpURLConnection）
   - 监控 SharedPreferences 读写
   - 监控加密操作（Cipher）

3. **JNI 定位与 Hook**
   - 监控 JNI RegisterNatives
   - Hook JNI 函数调用
   - 枚举已加载的 Native 库
   - Hook dlopen/dlsym

### 🎯 便捷功能

- ✅ 树形结构展示脚本分类
- ✅ 双击节点查看脚本内容
- ✅ 一键复制脚本到剪贴板
- ✅ 快捷键快速打开（`Ctrl+Alt+H`）
- ✅ 菜单栏集成
- ✅ 支持中文和英文界面

## 安装方法

### 方法 1：命令行安装（推荐）

```bash
# 编译插件
cd jadx-frida-hookAll
mvn clean package

# 安装到 JADX
jadx plugins --install-local target/jadx-frida-hookall-1.0.0.jar
```

### 方法 2：手动安装

1. 编译项目生成 JAR 文件
   ```bash
   mvn clean package
   ```

2. 打开 JADX GUI

3. 点击菜单：`Plugins` → `Install plugin`

4. 选择生成的 `target/jadx-frida-hookall-1.0.0.jar` 文件

5. 重启 JADX

## 使用方法

### 打开脚本模板窗口

有两种方式：

1. **快捷键**：按 `Ctrl+Alt+H` (H = Hook)
2. **菜单**：`Plugins` → `Frida Hook Templates`

### 使用脚本

1. 在左侧树形结构中浏览脚本分类
2. 双击任意脚本节点查看详细代码
3. 点击"复制脚本"按钮将脚本复制到剪贴板
4. 在 Frida 中使用该脚本：

```bash
# 将脚本保存为 hook.js
frida -U -f com.example.app -l hook.js
```

## 脚本示例

### 监控 Dialog 显示

```javascript
Java.perform(function() {
    var Dialog = Java.use('android.app.Dialog');
    
    Dialog.show.implementation = function() {
        console.log('========== Dialog.show() ==========');
        console.log('[Dialog] Stack trace:');
        console.log(Java.use('android.util.Log').getStackTraceString(
            Java.use('java.lang.Exception').$new()
        ));
        return this.show();
    };
});
```

### 监控 JNI RegisterNatives

自动追踪所有 JNI 方法的注册，包括：
- 注册的 Java 类名
- Native 方法名和签名
- Native 函数指针地址

## 项目结构

```
jadx-frida-hookAll/
├── pom.xml
├── README.md
└── src/main/java/com/frida/jadx/
    ├── JadxFridaHookAll.java      # 插件主类
    ├── FridaScriptDialog.java      # UI 对话框
    └── FridaTemplates.java         # 脚本模板库
```

## 技术实现

### 核心技术

- **插件机制**：Java SPI（Service Provider Interface）
- **UI 框架**：Swing（JTree + JDialog）
- **脚本管理**：静态模板库

### 快捷键实现

使用 Swing 的 `KeyStroke` API 注册全局快捷键：

```java
JMenuItem menuItem = new JMenuItem("Frida Hook Templates");
menuItem.setAccelerator(KeyStroke.getKeyStroke(
    KeyEvent.VK_H,  // H = Hook
    ActionEvent.CTRL_MASK | ActionEvent.ALT_MASK  // Ctrl+Alt+H
));
```

### 树形结构

使用 `DefaultMutableTreeNode` 和 `JTree` 实现三级分类：

```
Root
├── JDK API Hooks
│   ├── 打印堆栈
│   ├── 打印 Map
│   └── ...
├── Android API Hooks
│   ├── 监控 Dialog
│   └── ...
└── JNI 定位与 Hook
    ├── 监控 JNI 注册
    └── ...
```

## 扩展脚本

如需添加新的脚本模板，编辑 `FridaTemplates.java`：

```java
public static final String YOUR_NEW_SCRIPT = 
    "// 你的脚本描述\n" +
    "Java.perform(function() {\n" +
    "    // 你的 Frida 代码\n" +
    "});";
```

然后在 `FridaScriptDialog.loadScriptTemplates()` 中添加：

```java
jdkNode.add(createScriptNode("你的脚本名", FridaTemplates.YOUR_NEW_SCRIPT));
```

## 开发环境

- Java 11+
- Maven 3.6+
- JADX 1.5.1+

## 编译命令

```bash
# 清理并编译
mvn clean compile

# 打包
mvn package

# 跳过测试打包
mvn package -DskipTests
```

## 常见问题

### Q: 快捷键不生效？

A: 确保 JADX GUI 窗口处于激活状态。如果 `Ctrl+Alt+H` 仍然冲突，可以修改快捷键（见下一问）。

### Q: 如何修改快捷键？

A: 编辑 `JadxFridaHookAll.java` 文件中的快捷键设置：
```java
// 修改 VK_H 为其他按键，如 VK_J, VK_K 等
KeyEvent.VK_H
// 或修改组合键，如只用 Ctrl
ActionEvent.CTRL_MASK
```

### Q: 脚本复制后如何使用？

A: 将脚本保存为 `.js` 文件，然后使用 Frida 命令加载：
```bash
frida -U -f <包名> -l <脚本文件.js>
```

## 相关资源

- [JADX](https://github.com/skylot/jadx) - Android 反编译工具
- [Frida](https://frida.re/) - 动态插桩框架
- [Frida 官方文档](https://frida.re/docs/home/)

## 许可证

Apache 2.0 License

## 贡献

欢迎提交 Issue 和 Pull Request！

如果你有好的 Frida 脚本模板，欢迎贡献到项目中。

## 作者

基于 jadx-ai-mcp 项目架构开发
