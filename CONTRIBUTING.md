# 📝 如何添加新的 Frida 脚本

## 🎯 项目结构

```
jadx-frida-hookAll/
└── src/main/
    ├── java/com/frida/jadx/
    │   ├── templates/
    │   │   ├── ScriptLoader.java          # 脚本加载工具
    │   │   ├── HelperFunctions.java       # 1️⃣ 辅助函数
    │   │   ├── HookJDK.java               # 2️⃣ Hook JDK
    │   │   ├── HookAndroid.java           # 3️⃣ Hook Android
    │   │   └── FridaAdvanced.java         # 4️⃣ Frida 进阶
    │   ├── FridaTemplates.java            # 主模板类
    │   ├── FridaScriptDialog.java         # UI 对话框
    │   └── JadxFridaHookAll.java          # 插件主类
    └── resources/frida-scripts/
        ├── helpers/                       # 辅助函数 .js 文件
        ├── hook-jdk/                      # JDK Hook .js 文件
        ├── hook-android/                  # Android Hook .js 文件
        └── frida-advanced/                # Frida 进阶 .js 文件
```

## ✨ 添加新脚本（只需 3 步）

### 步骤 1：创建 .js 脚本文件

在对应的分类目录下创建 `.js` 文件：

```bash
# 例如：添加一个 Hook Toast 的脚本
src/main/resources/frida-scripts/hook-android/monitor-toast.js
```

文件内容示例：
```javascript
// Monitor Toast Messages
Java.perform(function() {
    var Toast = Java.use('android.widget.Toast');
    
    Toast.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int')
        .implementation = function(context, text, duration) {
            console.log('[Toast] Text: ' + text.toString());
            return this.makeText(context, text, duration);
        };
    
    console.log('[+] Toast monitor installed');
});
```

### 步骤 2：在对应的 Java 类中添加条目

编辑对应分类的 Java 文件，例如 `HookAndroid.java`：

```java
public static final ScriptEntry MONITOR_TOAST = new ScriptEntry(
    "Monitor Toast",  // 脚本显示名称
    ScriptLoader.loadScript(BASE_PATH + "monitor-toast.js")  // 加载 .js 文件
);
```

### 步骤 3：在 UI 中注册

编辑 `FridaScriptDialog.java`，在 `loadScriptTemplates()` 方法中添加：

```java
// Category 3: Hook Android
DefaultMutableTreeNode androidNode = new DefaultMutableTreeNode("3. Hook Android");
androidNode.add(createScriptNode(HookAndroid.MONITOR_DIALOG));
androidNode.add(createScriptNode(HookAndroid.MONITOR_TOAST));  // ← 添加这一行
```

### 完成！重新编译即可

```powershell
.\compile.ps1
```

## 📂 四大分类说明

### 1️⃣ Helper Functions（辅助函数）

**位置**：`src/main/resources/frida-scripts/helpers/`

**用途**：通用的辅助函数，可以在其他脚本中调用

**示例**：
- `print-stacktrace.js` - 打印堆栈
- `print-args.js` - 打印参数
- `bytes-to-hex.js` - 字节转十六进制

### 2️⃣ Hook JDK

**位置**：`src/main/resources/frida-scripts/hook-jdk/`

**用途**：Hook Java 标准库 API

**示例**：
- `print-map.js` - 打印 Map 内容
- `print-list.js` - 打印 List 内容
- `hook-string.js` - Hook String 操作

### 3️⃣ Hook Android

**位置**：`src/main/resources/frida-scripts/hook-android/`

**用途**：Hook Android Framework API

**示例**：
- `monitor-dialog.js` - 监控 Dialog
- `monitor-toast.js` - 监控 Toast
- `monitor-activity.js` - 监控 Activity 生命周期

### 4️⃣ Frida Advanced

**位置**：`src/main/resources/frida-scripts/frida-advanced/`

**用途**：Frida 高级特性（JNI、Native Hook 等）

**示例**：
- `jni-register-natives.js` - 监控 JNI 注册
- `enumerate-modules.js` - 枚举模块
- `hook-dlopen.js` - Hook dlopen

## 🔍 调试日志

插件会输出详细的调试日志：

```
[INFO] Loading Frida script templates...
[DEBUG] Loaded 3 Helper Functions scripts
[DEBUG] Loaded 1 Hook JDK scripts
[DEBUG] Loaded 1 Hook Android scripts
[DEBUG] Loaded 1 Frida Advanced scripts
[INFO] Script templates loaded successfully. Total categories: 4
```

如果脚本加载失败，会显示：
```
[ERROR] Script file not found: frida-scripts/xxx/xxx.js
[ERROR] Error loading script: xxx
```

## 💡 最佳实践

1. **文件命名**：使用小写和连字符，如 `monitor-toast.js`
2. **脚本注释**：在 .js 文件开头添加清晰的注释说明用途
3. **代码格式**：.js 文件使用标准 JavaScript 格式（不需要字符串拼接！）
4. **错误处理**：在 Hook 中添加 try-catch 避免崩溃
5. **日志输出**：使用 `console.log` 输出调试信息

## 🎨 优势

✅ **脚本独立**：每个 .js 文件独立，方便编辑和测试  
✅ **无字符串拼接**：直接写 JavaScript，不需要 Java 字符串拼接  
✅ **分类清晰**：4 大分类，结构清晰易维护  
✅ **调试友好**：详细的日志输出，快速定位问题  
✅ **易于扩展**：添加新脚本只需 3 步

## 🔧 常见问题

**Q: 脚本加载失败怎么办？**  
A: 检查 .js 文件路径是否正确，确保在 `resources/frida-scripts/` 目录下

**Q: 如何测试脚本是否正确？**  
A: 可以先用 Frida 命令行测试 .js 文件，确认无误后再集成

**Q: 可以在脚本中引用其他脚本吗？**  
A: 可以，使用 Frida 的 `Script.load()` 或将公共函数放到辅助函数分类中
