# JADX Frida HookAll Plugin

一个简单但实用的 JADX 插件，提供涉及到 Java 层的常用 Frida Hook 脚本，每天帮助你省5分钟翻笔记的时间；

组合快捷键 `Ctrl+Alt+H` 调出树形结构展示ui，提供复制剪切板和切换语言功能，实用且美观；

## 1. 脚本分类
- Helper Functions（辅助函数）
    - 打印堆栈
    - 打印参数
    - 字节转十六进制

- Hook JDK（JDK Api）
    - 打印 Map 内容

- Hook Android（Android Api）
    - 监控 Dialog

- Frida Advanced（Frida Api）
    - JNI RegisterNatives 监控


## 2.  编译与安装

### 2.1 准备 JADX JAR

编译需要 JADX 的 JAR 文件，可从以下位置获取：
- **已安装的 JADX**：`~/.local/share/jadx/lib/jadx-gui-*.jar`（Linux）
- **JADX 源码**：`jadx/jadx-gui/build/libs/jadx-gui-dev-all.jar`
- **下载发布版**：https://github.com/skylot/jadx/releases

### 2.2 编译插件

**Windows：**
```powershell
# 方式1：使用默认路径（脚本内配置）
.\compile.ps1

# 方式2：指定 JAR 路径
.\compile.ps1 "C:\path\to\jadx-gui.jar"

# 方式3：使用环境变量
$env:JADX_GUI_JAR="C:\path\to\jadx-gui.jar"
.\compile.ps1
```

**Linux/Mac：**
```bash
chmod +x compile.sh

# 方式1：自动查找（常见路径）
./compile.sh

# 方式2：指定 JAR 路径
./compile.sh /path/to/jadx-gui.jar

# 方式3：使用环境变量
export JADX_GUI_JAR=/path/to/jadx-gui.jar
./compile.sh
```

### 2.3 安装插件
在 JADX GUI 中：`Plugins` → `Install plugin` → 选择 `target/jadx-frida-hookall-1.0.0.jar` 

> 如需更新插件，需要先卸载插件然后重启jadx，再次重新安装即可；


## 3.  脚本示例

1. 打印堆栈

    ```javascript
    function showJavaStacks() {
        console.log(Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new()));
    }
    ```

2.  监控 Dialog

    ```javascript
    Java.perform(function() {
        Java.use('android.app.Dialog').show.implementation = function() {
            console.log('[Dialog] show() called');
            showJavaStacks();
            return this.show();
        };
    });
    ```

## 4. 扩展开发
只需要3步就行；我们接下来以监控弹窗为例；
### 4.1 创建脚本文件

创建 `src/main/resources/frida-scripts/hook-android/monitor-toast.js`

**可以在脚本内编写注释用于解释hook的作用**，在代码中可以标记贡献者id；

### 4.2 注册脚本

编辑 `HookAndroid.java`：
```java
public static final ScriptEntry MONITOR_TOAST = new ScriptEntry(
    "Monitor Toast",
    ScriptLoader.loadScript(BASE_PATH + "monitor-toast.js")
);
```

### 4.3 添加到ui树

编辑 `FridaScriptDialog.java`：
```java
androidNode.add(createScriptNode(HookAndroid.MONITOR_TOAST));
```

如果还是理解不了，可以参考下面的项目结构
```
src/main/
├── java/com/frida/jadx/
│   ├── JadxFridaHookAll.java      # 插件入口
│   ├── FridaScriptDialog.java     # UI 对话框
│   ├── PluginConfig.java          # 配置管理
│   └── templates/
│       ├── HelperFunctions.java   # 辅助函数
│       ├── HookJDK.java
│       ├── HookAndroid.java
│       └── FridaAdvanced.java
└── resources/frida-scripts/
    ├── helpers/
    ├── hook-jdk/
    ├── hook-android/
    └── frida-advanced/
```

### 4.4 提交贡献（可选）
- 提交PR（推荐）
- q群反馈：686725227

## 许可证
Apache 2.0 License
