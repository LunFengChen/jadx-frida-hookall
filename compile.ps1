# JADX Frida HookAll 编译脚本
Write-Host "========== JADX Frida HookAll 编译 ==========" -ForegroundColor Cyan

$jadxGuiJar = "C:\Users\xiaofeng\Desktop\projects\jadx\jadx-gui\build\libs\jadx-gui-dev-all.jar"

# 检查 JADX JAR 是否存在
if (-not (Test-Path $jadxGuiJar)) {
    Write-Host "✗ JADX JAR 文件不存在: $jadxGuiJar" -ForegroundColor Red
    exit 1
}

Write-Host "✓ 找到 JADX: $jadxGuiJar" -ForegroundColor Green

# 步骤 1: 创建 lib 目录并复制 JADX
Write-Host "`n[1/2] 准备 JADX 库..." -ForegroundColor Yellow

$libDir = ".\lib"
if (-not (Test-Path $libDir)) {
    New-Item -ItemType Directory -Path $libDir | Out-Null
    Write-Host "✓ 创建 lib 目录" -ForegroundColor Green
}

Copy-Item $jadxGuiJar -Destination "$libDir\jadx-gui.jar" -Force
Write-Host "✓ 复制 JADX 库到 lib\jadx-gui.jar" -ForegroundColor Green

# 步骤 2: 编译项目
Write-Host "`n[2/2] 编译项目..." -ForegroundColor Yellow
.\mvnw.cmd clean package -DskipTests

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "✓ 编译成功!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    
    $jarFile = Get-Item ".\target\jadx-frida-hookall-1.0.0.jar"
    Write-Host "`n生成的插件文件:" -ForegroundColor Yellow
    Write-Host "  路径: $($jarFile.FullName)" -ForegroundColor White
    Write-Host "  大小: $([math]::Round($jarFile.Length / 1KB, 2)) KB" -ForegroundColor Gray
    
    Write-Host "`n安装到 JADX:" -ForegroundColor Yellow
    Write-Host "  方法1 - 命令行:" -ForegroundColor Cyan
    Write-Host "    cd C:\Users\xiaofeng\Desktop\projects\jadx" -ForegroundColor White
    Write-Host "    .\gradlew.bat runJadx" -ForegroundColor White
    Write-Host "    然后在 JADX GUI 中: Plugins -> Install plugin -> 选择上面的 jar 文件`n" -ForegroundColor White
    
    Write-Host "  方法2 - 手动复制:" -ForegroundColor Cyan
    Write-Host "    将 jar 复制到: C:\Users\xiaofeng\Desktop\projects\jadx\jadx-gui\build\jadx-gui-win\plugins\" -ForegroundColor White
    
} else {
    Write-Host "`n✗ 编译失败" -ForegroundColor Red
    exit 1
}
