# 电脑版 ↔ 手机版 同步脚本
# 把最新 kboxObfPro\dist 的混淆器 jar 同步进 mobile-monitor 目录的 dist 参考副本，
# 并回显当前使用版本，保证电脑版与手机版能力一致。
$ErrorActionPreference = "Stop"

$Here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$SrcDir = Join-Path $Here "..\kboxObfPro\dist"
$DstDir = Join-Path $Here "dist"

if (-not (Test-Path $SrcDir)) {
    Write-Host "未找到源目录: $SrcDir" -ForegroundColor Yellow
    exit 1
}

New-Item -ItemType Directory -Force -Path $DstDir | Out-Null

$jars = Get-ChildItem -Path $SrcDir -Filter "kboxObfusc*.jar" | Sort-Object LastWriteTime -Descending
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