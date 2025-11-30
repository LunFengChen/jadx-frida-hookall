/*
 * Hook dlopen - 监控 SO 加载
 * 监控动态库加载过程，可用于分析加固、反调试等场景
 */

function hook_dlopen(targetSoName) {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            this.fileName = args[0].readCString();
            console.log(`[+] dlopen onEnter ==> ${this.fileName}`);

            if (!targetSoName || this.fileName.indexOf(targetSoName) >= 0) {
                this.isMatch = true;
            }
        }, 
        onLeave: function (retval) {
            console.log(`[-] dlopen onLeave <== ${this.fileName}`);

            // 对匹配的 SO 进行详细监控
            if (this.isMatch) {
                let address_JNI_OnLoad = Module.getExportByName(this.fileName, 'JNI_OnLoad');
                console.warn(`[*] found JNI_OnLoad in ${this.fileName}, address is at ${address_JNI_OnLoad}`);

                // 认为目标so都有JNI_OnLoad，Hook JNI_OnLoad
                Interceptor.attach(address_JNI_OnLoad, {
                    onEnter: function (args) {
                            console.log(`\t[->] ${this.fileName} JNI_OnLoad onEnter`);
                            // 这里可以继续你的分析逻辑
                            // 例如：inline hook、dump 内存、hook 其他函数、修改数据等
                        },
                    onLeave: function () {
                        console.log(`\t[<-] ${this.fileName} JNI_OnLoad onLeave`);
                    }
                });
            }
        }
    });
}

// 启动 Hook
// hook_dlopen();
// hook_dlopen("libdexprotector.so");

/*
 * 使用说明：
 * 
 * 1. 监控所有 SO 的加载（不指定目标）
 *    hook_dlopen();
 * 
 * 2. 默认监控所有so， 目标so监控JNI_OnLoad
 *    hook_dlopen("libdexprotector.so");
 * 
 * 3. 运行脚本
 *    frida -U -f com.example.app -l hook_dlopen.js
 * 
 * 应用场景：
 * - 监控加固 SO 的加载时机
 * - Hook SO 的 JNI_OnLoad 初始化函数
 * - 分析 SO 加载顺序和依赖关系
 * - 在 SO 加载后立即进行 Hook 或 Dump
 * 
 * 注意事项：
 * - 如果不传参数，会监控所有 SO 并尝试 Hook 所有 JNI_OnLoad
 * - 建议先不传参数观察所有 SO，再针对目标 SO 进行监控
 */
