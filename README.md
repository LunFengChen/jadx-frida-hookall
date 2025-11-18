# JADX Frida HookAll Plugin

一个简单但实用的 JADX 插件，提供涉及到 Java 层的常用 Frida Hook 脚本，每天帮助你省5分钟翻笔记的时间；

组合快捷键 `Ctrl+Alt+H` 调出树形结构展示ui，提供复制剪切板和切换语言功能，实用且美观；
> 对你有用的话给个star吧或者分享一下，感谢哇；

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


## 2. 安装方法

### 方式 1：直接下载安装（推荐）

1. 从 [Releases](https://github.com/LunFengChen/jadx-frida-hookAll/releases) 页面下载最新的 `jadx-frida-hookall-x.x.x.jar`
2. 在 JADX GUI 中：`Plugins` → `Install plugin` → 选择下载的 JAR 文件
3. 重启 JADX

### 方式 2：手动编译安装

如果你想修改插件或贡献代码，请查看 [4. 扩展开发](#4-扩展开发) 章节。

> **更新插件**：先卸载旧版本，重启 JADX，再安装新版本。


## 3. 使用方法

### 3.1 打开插件

两种方式：
- **快捷键**：`Ctrl+Alt+H`
- **菜单**：`Plugins` → `Frida Hook Templates`

### 3.2 使用脚本

1. 单击树节点查看脚本
2. 点击"复制脚本"按钮
3. 保存为 `.js` 文件
4. 使用 Frida 加载：

```bash
frida -U -f com.example.app -l hook.js
```

### 3.3 切换语言

- 插件会自动跟随 JADX 的语言设置
- 也可以点击左下角按钮手动切换中英文


## 4. 脚本示例

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

## 5. 扩展开发

想要添加新脚本或修改插件？只需 3 步！

### 5.1 添加新脚本

以添加"监控 Toast"为例：

#### 步骤 1：创建脚本文件

创建 `src/main/resources/frida-scripts/hook-android/monitor-toast.js`

```javascript
// Monitor Toast messages
// Author: YourName
Java.perform(function() {
    var Toast = Java.use('android.widget.Toast');
    Toast.show.implementation = function() {
        console.log('[Toast] ' + this.mText.value);
        return this.show();
    };
});
```

#### 步骤 2：注册脚本

编辑 `HookAndroid.java`：
```java
public static final ScriptEntry MONITOR_TOAST = new ScriptEntry(
    "Monitor Toast",
    ScriptLoader.loadScript(BASE_PATH + "monitor-toast.js")
);
```

#### 步骤 3：添加到 UI 树

编辑 `FridaScriptDialog.java` 的 `loadScriptTemplates()` 方法：
```java
androidNode.add(createScriptNode(HookAndroid.MONITOR_TOAST));
```

### 5.2 编译插件

#### 准备 JADX JAR

编译需要 JADX 的 JAR 文件：
- **JADX 源码**：`jadx/jadx-gui/build/libs/jadx-gui-dev-all.jar`
- **已安装的 JADX**：`~/.local/share/jadx/lib/jadx-gui-*.jar`（Linux）
- **下载发布版或者二改版**：
    - https://github.com/skylot/jadx/releases
    - https://github.com/LunFengChen/jadx/releases

#### Windows 编译

```powershell
# 使用默认路径
.\compile.ps1

# 或指定 JAR 路径
.\compile.ps1 "C:\path\to\jadx-gui.jar"
```

#### Linux/Mac 编译

```bash
chmod +x compile.sh

# 自动查找
./compile.sh

# 或指定路径
./compile.sh /path/to/jadx-gui.jar
```

生成的插件：`target/jadx-frida-hookall-1.0.0.jar`

### 5.3 项目结构

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

### 5.4 贡献方式

- **提交 PR**：https://github.com/LunFengChen/jadx-frida-hookAll
- **反馈交流**：Q群 686725227


## 6. 常见问题

**Q: 快捷键不生效？**
- 确保 JADX 窗口处于激活状态
- 或使用菜单：`Plugins` → `Frida Hook Templates`

**Q: 如何切换语言？**
- 插件自动跟随 JADX 语言设置
- 或点击左下角按钮手动切换

## 许可证
Apache 2.0 License
