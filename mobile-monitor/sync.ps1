# 电脑版 ↔ 手机版 同步脚本
# 把最新 dist（原始代码\dist\release-v3.0.1 或 kbox-cli\target）的混淆器 jar 同步进 mobile-monitor 目录的 dist 参考副本，
# 并回显当前使用版本，保证电脑版与手机版能力一致。
$ErrorActionPreference = "Stop"

$Here   = Split-Path -Parent $MyInvocation.MyCommand.Path
# 依优先级寻找电脑版产物目录（新版 dist / Maven 构建产物 / 历史 kboxObfPro）。
$Candidates = @(
    (Join-Path $Here "..\原始代码\dist\release-v3.0.1"),
    (Join-Path $Here "..\高级先行版源码\kbox-cli\target"),
    (Join-Path $Here "..\kboxObfPro\dist")
)
$SrcDir = $Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
$DstDir = Join-Path $Here "dist"

if (-not (Test-Path $SrcDir)) {
    Write-Host "未找到源目录: $SrcDir" -ForegroundColor Yellow
    exit 1
}

New-Item -ItemType Directory -Force -Path $DstDir | Out-Null

$jars = Get-ChildItem -Path $SrcDir -Filter "kbox*.jar" | Sort-Object LastWriteTime -Descending
if (-not $jars) {
    Write-Host "未在 $SrcDir 下找到 kboxObfusc*.jar" -ForegroundColor Yellow
    exit 1
}

# 只同步「未保护」的混淆器 jar（排除 -protected 产物）
$main = $jars | Where-Object { $_.Name -notmatch "protected" } | Select-Object -First 1
if (-not $main) { $main = $jars | Select-Object -First 1 }

Copy-Item -Path $main.FullName -Destination (Join-Path $DstDir $main.Name) -Force
Write-Host "已同步: $($main.Name)" -ForegroundColor Green
Write-Host "      源: $($main.FullName)"
Write-Host ""
Write-Host "当前电脑版/手机版所依据的协议版本见 docs/PROTOCOL.md（schema 一致即同步）。"