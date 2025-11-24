# JADX Frida HookAll Plugin

一个简单但实用的 JADX 插件，提供涉及到 Java 层的常用 Frida Hook 脚本，帮助你节省翻笔记的时间。

组合快捷键 `Ctrl+Alt+H` 调出树形结构展示 UI，提供复制剪切板和切换语言功能，实用且美观。

> 觉得有用的话给个 Star 或分享一下，感谢！
> 欢迎提 Issue 或 PR 贡献更多脚本。

## 1. 脚本分类

插件目前提供 **8 大分类**，包含 **50+** 个常用 Frida Hook 脚本：

| 分类 | 英文名称 | 中文名称 | 脚本数 | 说明 |
|------|---------|---------|--------|------|
| 1️⃣ | **Frida Basic Use** | Frida基本使用 | 6 | 基础 Hook 模板、重载、构造函数、字段、内部类、类枚举 |
| 2️⃣ | **Helper Functions** | 辅助函数 | 8 | 打印堆栈、参数、Map、数组、方法签名、对象详情等 |
| 3️⃣ | **Hook JDK** | Hook JDK | 15 | String, Map, List, File, URL, Base64, Crypto, Process, Thread, JSON 等 |
| 4️⃣ | **Hook Android** | Hook Android | 11 | Activity, Dialog, Toast, Log, SharedPreferences, Base64, Crash, WebView 等 |
| 5️⃣ | **Hook Third-Party** | Hook第三方库 | 2 | OkHttp, JSONObject |
| 6️⃣ | **Hook JNI** | JNI相关 | 0 | (待添加) |
| 7️⃣ | **Frida Advanced** | Frida进阶 | 5 | 主动调用、ClassLoader、Dump证书、LoadDex、JNI Register |
| 8️⃣ | **Bypass Check** | 绕过检测 | 1 | Bypass MSA 等 |

<details>
<summary>📋 点击查看详细脚本列表</summary>

### 1️⃣ Frida Basics（Frida基本使用）
- Hook 普通方法
- Hook 重载方法
- Hook 构造函数
- Hook 字段
- Hook 内部类
- 枚举类和方法

### 2️⃣ Helper Functions（辅助函数）
- 打印调用栈
- 数据格式转换（Hex/String/Base64）
- 打印方法参数
- 打印 Map 对象
- 打印字符串数组
- 打印方法签名
- 打印自定义对象
- 打印对象数组

### 3️⃣ Hook JDK（Hook JDK）
- 监控 String (高级过滤)
- 监控 StringBuilder
- 监控 StringFactory
- 监控 Base64 (Java)
- 监控 URL
- 监控 File (读写删)
- 监控所有 Map (Put/Get)
- 监控 ArrayList
- 监控 Collections
- 打印 Map
- 监控 JSON
- 监控 Crypto (加解密)
- 监控 Process (命令执行)
- 监控 System.load
- 监控 Thread

### 4️⃣ Hook Android（Hook Android）
- 监控 Base64 (Android)
- 监控 Activity
- 监控 Dialog
- 监控 Toast
- 监控 EditText
- 监控 WebView
- 监控 Log
- 监控 TextUtils
- 监控 SharedPreferences
- 阻止弹窗
- 监控 Crash

### 5️⃣ Hook Third-Party（Hook第三方库）
- 监控 OkHttp
- 监控 JSONObject

### 6️⃣ Hook JNI（JNI相关）
- (待添加)

### 7️⃣ Frida Advanced（Frida进阶）
- 主动调用方法
- ClassLoader 辅助
- Dump 证书
- 动态加载 DEX
- 监控 JNI RegisterNatives

### 8️⃣ Bypass Check（绕过检测）
- Bypass MSA

</details>

## 2. 安装方法

### 方式 1：jadx-cli 安装（推荐）

```bash
# 直接从 GitHub 安装最新版
jadx plugins --install "github:LunFengChen:jadx-frida-hookAll"
```

### 方式 2：GUI 安装

1. 打开 JADX GUI → `Preferences` → `Plugins`
2. 点击 `Install plugin` 按钮
3. 输入 locationId：`github:LunFengChen:jadx-frida-hookAll`
4. 点击 `Install` 并重启 JADX

### 方式 3：离线安装

1. 从 [Releases](https://github.com/LunFengChen/jadx-frida-hookAll/releases) 下载最新版本的 JAR 文件。
2. JADX GUI: `Plugins` → `Install plugin` → 选择下载的 JAR 文件。
3. 重启 JADX。

## 3. 使用方法

### 3.1 打开插件
- **快捷键**：`Ctrl+Alt+H`
- **菜单**：`Plugins` → `Frida实用脚本库` (Frida Script Library)

### 3.2 使用脚本
1. 在左侧树形菜单中选择分类和脚本。
2. 右侧预览脚本内容。
3. 点击下方 **"复制脚本"** 按钮（支持一键去除注释复制）。
4. 将代码粘贴到你的 Frida 脚本文件中。

### 3.3 切换语言
插件界面支持 **中文/English** 双语，会自动跟随 JADX 的语言设置，也可以点击左下角按钮手动切换。

## 4. 目录结构

```
src/main/
├── java/com/frida/jadx/templates/
│   ├── HookJDK.java           # JDK 脚本注册
│   ├── HookAndroid.java       # Android 脚本注册
│   └── ...
└── resources/frida-scripts/
    ├── 01-frida-basicUse/     # 基础使用
    ├── 02-helper-functions/   # 辅助函数
    ├── 03-hook-jdk/           # JDK Hooks
    ├── 04-hook-android/       # Android Hooks
    ├── 05-hook-third-party/   # 第三方库
    ├── 07-frida-advancedApi/  # 进阶 API
    └── 08-bypass-check/       # 绕过检测
```

## 5. 贡献
欢迎提交 PR 补充更多实用的 Frida 脚本！

1. 在 `src/main/resources/frida-scripts/` 下对应的分类文件夹中添加 `.js` 脚本。
2. 在 `src/main/java/com/frida/jadx/templates/` 对应的 Java 类中注册脚本。
3. 在 `FridaScriptDialog.java` 中添加到 UI 树。

## 许可证
Apache 2.0 License
