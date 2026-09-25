# 一键构建 KBox 手机监控 APK
# 作用：
#   1) 检测/自动安装 Android SDK（本机首次需联网下载）
#   2) 生成本地 sdk.dir 配置
#   3) 用系统 Gradle 编译出可安装的 app-debug.apk（在 apk-source/app/build/outputs/apk/debug/）
# 前置：已安装 JDK 17+ 与 Gradle（本机已具备 gradle）。若未安装 Gradle，脚本会尝试引导。
# 用法：  powershell -ExecutionPolicy Bypass -File build-apk.ps1

$ErrorActionPreference = "Stop"
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjDir     = Join-Path $ScriptDir "..\apk-source"
$SdkDir      = Join-Path $ScriptDir "..\android-sdk"
$CmdlineUrl  = "https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip"
$ZipPath     = Join-Path $ScriptDir "cmdline-tools.zip"

Write-Host "=== KBox 手机监控 APK 构建 ===" -ForegroundColor Green

# ---- 1. 定位或安装 Android SDK ----
$sdk = $null
foreach ($envVar in @($env:ANDROID_HOME, $env:ANDROID_SDK_ROOT)) {
    if ($envVar -and (Test-Path $envVar)) { $sdk = $envVar; break }
}
if (-not $sdk) { $sdk = $SdkDir }
Write-Host "[1/4] Android SDK: $sdk"

if (-not (Test-Path (Join-Path $sdk "platform-tools")) -or
    -not (Test-Path (Join-Path $sdk "platforms\android-34"))) {
    Write-Host "      未检测到可用 SDK，开始自动安装（首次需联网）..." -ForegroundColor Yellow
    if (-not (Test-Path $ZipPath)) {
        Write-Host "      下载 commandline-tools ..."
        Invoke-WebRequest -Uri $CmdlineUrl -OutFile $ZipPath
    }
    $clt = Join-Path $sdk "cmdline-tools\latest"
    New-Item -ItemType Directory -Force -Path $clt | Out-Null
    $tmp = Join-Path $sdk "cmdline-tools\_tmp"
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    Expand-Archive -Path $ZipPath -DestinationPath $tmp -Force
    Get-ChildItem -Path (Join-Path $tmp "cmdline-tools\bin") | Move-Item -Destination $clt -Force
    Remove-Item -Recurse -Force $tmp
    try { Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue } catch {}
    $sm  = Join-Path $clt "bin\sdkmanager.bat"
    $y   = "y"
    "y`ny`ny`n" | & $sm --licenses | Out-Null
    & $sm "platform-tools" "platforms;android-34" "build-tools;34.0.0" | Out-Null
}
Write-Host "      SDK 就绪。"

# ---- 2. 写入 local.properties ----
$localProps = Join-Path $ProjDir "local.properties"
$sdkPathForProps = $sdk.Replace('\','/')
Set-Content -Path $localProps -Value ("sdk.dir=" + $sdkPathForProps) -Encoding UTF8
Write-Host "[2/4] 已写入 local.properties (sdk.dir=$sdkPathForProps)"

# ---- 3. 生成 gradle wrapper（若环境无 gradle）----
$gradle = Get-Command gradle -ErrorAction SilentlyContinue
if ($gradle) {
    Write-Host "[3/4] 使用系统 Gradle: $($gradle.Source)"
} else {
    Write-Host "[3/4] 未找到系统 Gradle，将尝试用 wrapper 构建（需先安装 Gradle）。" -ForegroundColor Yellow
    throw "未找到 gradle 命令。请先安装 Gradle 8.x：https://gradle.org/install/"
}

# ---- 4. 构建 ----
Write-Host "[4/4] 编译 debug APK ..." -ForegroundColor Green
Push-Location $ProjDir
try {
    & gradle assembleDebug --console=plain
    if ($LASTEXITCODE -ne 0) { throw "Gradle 构建失败，退出码 $LASTEXITCODE" }
} finally {
    Pop-Location
}

$apk = Join-Path $ProjDir "app\build\outputs\apk\debug\app-debug.apk"
if (Test-Path $apk) {
    Write-Host ""
    Write-Host "=== 构建成功 ===" -ForegroundColor Green
    Write-Host "APK: $apk"
    Write-Host "  可安装文件：app-debug.apk（侧载安装即可，局域网内连 PC 监控地址即可使用）"
} else {
    Write-Host "未找到产物 APK，请检查构建日志。" -ForegroundColor Yellow
}