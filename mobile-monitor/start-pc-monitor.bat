@echo off
chcp 65001 >nul
REM 双击启动电脑版混淆器 GUI + 内嵌手机远程监控服务（含 /api/pair、/api/stream SSE）。
REM 优先使用本目录 dist\kbox-protector.jar（带监控代码），否则退回 kboxObfPro\dist。
REM 用法：直接双击 或  启动"本.bat" "D:\path\kboxObfuscator.jar"  [额外JVM参数]

setlocal
cd /d "%~dp0"

set "JAR=%~1"
if "%JAR%"=="" set "JAR=%~dp0dist\kbox-protector.jar"
if not exist "%JAR%" (
    for /f "delims=" %%f in ('powershell -NoProfile -Command "Get-ChildItem '..\kboxObfPro\dist' -Filter 'kboxObfusc*.jar' | Where-Object {$_.Name -notmatch 'protected'} | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName"') do set "JAR=%%f"
)
if "%JAR%"=="" (
    echo [错误] 未找到混淆器 jar。请先构建电脑版，或把 jar 传入作为参数。
    pause
    exit /b 1
)
if not exist "%JAR%" (
    echo [错误] 找不到 jar: %JAR%
    pause
    exit /b 1
)

echo 启动电脑版混淆器(含手机远程监控服务): %JAR%
echo 启动后请留意控制台打印的「手机监控连接串」 http://电脑IP:端口/?token=xxxx
echo 手机端装好 KBoxMonitor APK 后，手输该地址或扫监控页二维码即可实时查看混淆进度。
echo.

java -jar "%JAR%" --gui %2 %3 %4 %5
pause