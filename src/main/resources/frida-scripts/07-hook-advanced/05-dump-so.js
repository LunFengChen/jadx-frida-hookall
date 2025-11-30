/*
 * Dump SO 文件到 /sdcard/Download/ 目录
 * 自动获取 SO 的基地址和大小信息
 */

// 统计全局 dump 了几个 so，防止同名的 so 被覆盖
var dump_num = 1;

function dump_so(so_name) {
    console.warn(`[*] ========== Dumping ${so_name} ... ========== `);
    // 获取模块信息
    var libso = Process.getModuleByName(so_name);
    // 直接写入 /sdcard/Download/ 目录（无需 root，无需复制）
    var file_path = "/sdcard/Download/" + libso.name + "_" + libso.base + "_" + ptr(libso.size) + "_" + dump_num + ".so";
    // 创建文件
    var file_handle = new File(file_path, "wb");
    if (file_handle && file_handle != null) {
        // 修改内存保护为可读
        Memory.protect(ptr(libso.base), libso.size, "rwx");
        
        // 读取 SO 内存
        var libso_buffer = ptr(libso.base).readByteArray(libso.size);
        
        // 写入文件
        file_handle.write(libso_buffer);
        file_handle.flush();
        file_handle.close();
        
        console.log("[dump]:", file_path);
    } else {
        console.error("[!] Failed to create file!");
    }
    
    dump_num++;
    console.warn(`[*] ========== Dump ${so_name} completely ========== `);
}

/*
 * 使用步骤：
 * 
 * 1. 代码 copy 进入 frida 控制台
 * 2. 调用函数 dump 指定 so
 *    dump_so("libxyass.so")
 * 
 * 3. 文件会自动保存到 /sdcard/Download/ 目录，直接拉取即可
 *    adb pull /sdcard/Download/libxyass_*.so
 * 
 * 4. 使用 SoFixer 修复 SO（根据架构选择 32/64 位）
 *    .\SoFixer64-Windows.exe -m <基地址> -s <待修复so文件路径> -o <修复后so文件路径>
 * 
 * 示例：
 *    .\SoFixer64-Windows.exe -m 0x7b12345000 -s libxyass.so -o libxyass_fixed.so
 * 
 * 优点：
 * - 自动记录 dump 次数，防止同名 SO 被覆盖
 * - 文件名包含基地址和大小，方便 SoFixer 修复
 * - 直接写入 /sdcard/Download/，无需 root 复制
 */
