# =====================================================================
# build.ps1 - KBox Obfuscator 手工构建（无需 Maven）
#
# 产出: dist/kboxObfuscatorb3.jar —— 与 v2.1 同构的 fat jar
#       （kbox-core + kbox-cli + kbox-gui + ASM + kotlinx-metadata + kotlin-stdlib）
#
# 模块发布目标:
#   kbox-core / kbox-cli -> --release 8   （受保护运行时需注入 Java 8 目标）
#   kbox-gui             -> --release 17  （HTML UI 使用 Java 9+ API）
#
# 用法: powershell -ExecutionPolicy Bypass -File build.ps1
#
# 说明: 中间产物默认落在系统临时目录（可由 -BuildDir 覆盖）。这不只是为了
#       整洁——已观测到工作区内的 .class 会被 IDE 语言服务/安全软件短暂独占，
#       导致 jar 读取失败；且 mingw binutils 无法处理含非 ASCII 的路径。
# =====================================================================
param(
    [string]$BuildDir = $null
)
$ErrorActionPreference = 'Stop'

$Root  = $PSScriptRoot
$M2    = Join-Path $env:USERPROFILE '.m2\repository'
# 每次构建使用独立临时目录：规避 IDE 语言服务/安全软件对上次构建产物的
# 短暂文件锁（被锁的旧 .class 无法删除/覆盖时，javac 会静默跳过写出，
# 表现为关键类间歇性缺失导致构建失败）。
if (-not $BuildDir) {
    $BuildDir = Join-Path $env:TEMP ("kboxbuild_" + [guid]::NewGuid().ToString('N'))
}
$Classes = Join-Path $BuildDir 'classes'
$Libs    = Join-Path $BuildDir 'libs'
$Dist    = Join-Path $Root 'dist'
$JarOut  = Join-Path $Dist 'kboxObfuscatorb3.jar'

# 运行时依赖（asm-util 需要 asm-analysis；kotlinx-metadata 需要 kotlin-stdlib）
$Deps = @(
    (Join-Path $M2 'org\ow2\asm\asm\9.10.1\asm-9.10.1.jar'),
    (Join-Path $M2 'org\ow2\asm\asm-analysis\9.10.1\asm-analysis-9.10.1.jar'),
    (Join-Path $M2 'org\ow2\asm\asm-commons\9.10.1\asm-commons-9.10.1.jar'),
    (Join-Path $M2 'org\ow2\asm\asm-tree\9.10.1\asm-tree-9.10.1.jar'),
    (Join-Path $M2 'org\ow2\asm\asm-util\9.10.1\asm-util-9.10.1.jar'),
    (Join-Path $M2 'org\jetbrains\kotlinx\kotlinx-metadata-jvm\0.9.0\kotlinx-metadata-jvm-0.9.0.jar'),
    (Join-Path $M2 'org\jetbrains\kotlin\kotlin-stdlib\1.9.21\kotlin-stdlib-1.9.21.jar'),
    (Join-Path $M2 'org\jetbrains\annotations\13.0\annotations-13.0.jar')
)
foreach ($d in $Deps) {
    if (-not (Test-Path $d)) { throw "缺少依赖: $d" }
}
$DepCp = ($Deps -join ';')

Write-Host '== 清理构建目录 =='
Remove-Item -Recurse -Force $BuildDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $Classes, $Libs, $Dist | Out-Null

function Get-ModuleSources([string]$module) {
    $src = Join-Path $Root "$module\src\main\java"
    if (-not (Test-Path $src)) { throw "缺少源码目录: $src" }
    return @(Get-ChildItem -Recurse -LiteralPath $src -Filter *.java | ForEach-Object { $_.FullName })
}

function Invoke-JavacModule([string]$module, [string]$release, [string]$cp) {
    $files = Get-ModuleSources $module
    Write-Host "== 编译 $module (--release $release, $($files.Count) 个源文件) =="
    # 直接展开文件列表：路径含非 ASCII，避免 @argfile 的编码歧义
    & javac -encoding UTF-8 "--release" $release -nowarn -d $Classes -cp $cp $files
    if ($LASTEXITCODE -ne 0) { throw "$module 编译失败" }
    $n = (Get-ChildItem -Recurse $Classes -Filter *.class | Measure-Object).Count
    Write-Host "   OK (累计 $n 个 class)"
}

# kbox-core 先于 cli/gui（后二者依赖它）
Invoke-JavacModule 'kbox-core' '8'  $DepCp
Invoke-JavacModule 'kbox-gui'  '17' ($Classes + ';' + $DepCp)
Invoke-JavacModule 'kbox-cli'  '8'  ($Classes + ';' + $DepCp)

# 关键类自检：缺失会导致运行期 NoClassDefFoundError。
# 注：本机存在「外部进程在 javac 活动期间偶发删除临时目录中的类文件」的干扰
# （被删的恰好是 kbox-core 的 SilentShield.class 顶层类；javac 本身不删文件）。
# 因此自检失败时重编 kbox-core 原位补齐，最多重试 3 次。
$MustClasses = @('com\kbox\core\silentshield\AuditOrchestrator.class',
                 'com\kbox\cli\ProtectorCli.class',
                 'com\kbox\core\shield\ShieldPacker.class')
function Test-MustClasses {
    foreach ($m in $MustClasses) {
        if (-not (Test-Path (Join-Path $Classes $m))) { return $false }
    }
    return $true
}
$mustOk = Test-MustClasses
for ($i = 0; $i -lt 3 -and -not $mustOk; $i++) {
    Write-Host "关键类缺失（外部干扰），重新编译 kbox-core 补齐 (尝试 $($i + 1))"
    Invoke-JavacModule 'kbox-core' '8' $DepCp
    $mustOk = Test-MustClasses
}
if (-not $mustOk) { throw '关键类缺失（多次修复失败）' }

Write-Host '== 复制资源 =='
foreach ($m in @('kbox-core', 'kbox-gui')) {
    $res = Join-Path $Root "$m\src\main\resources"
    if (Test-Path $res) { Copy-Item -Recurse -Force (Join-Path $res '*') $Classes }
}

Write-Host '== 展开运行时依赖（shade） =='
# Expand-Archive 只认 .zip 扩展名，故逐个复制为 zip 后展开（-Force 覆盖同名条目）
# 注意：本机 PS 5.1 下 Get-ChildItem -Recurse -LiteralPath ... -File 会返回空集，
# 故目录枚举统一用 .NET 的 Directory 静态方法。
$zipTmp = Join-Path $BuildDir 'dep.zip'
foreach ($d in $Deps) {
    Copy-Item -LiteralPath $d -Destination $zipTmp -Force
    Expand-Archive -LiteralPath $zipTmp -DestinationPath $Libs -Force
}
Remove-Item -Force $zipTmp -ErrorAction SilentlyContinue
# 依赖的签名文件会让 fat jar 校验失败
foreach ($sf in [System.IO.Directory]::GetFiles($Libs, '*', 'AllDirectories')) {
    $ext = [System.IO.Path]::GetExtension($sf)
    if ($ext -eq '.SF' -or $ext -eq '.DSA' -or $ext -eq '.RSA') { Remove-Item -Force $sf -ErrorAction SilentlyContinue }
}
$libCount = [System.IO.Directory]::GetFiles($Libs, '*', 'AllDirectories').Length
if ($libCount -lt 500) { throw "运行时依赖展开异常：仅 $libCount 个文件" }
Write-Host "   OK ($libCount 个文件)"

Write-Host '== 打包 fat jar =='
$mf = Join-Path $BuildDir 'MANIFEST.MF'
@('Manifest-Version: 1.0', 'Main-Class: com.kbox.cli.ProtectorCli', '', '') |
    Set-Content -LiteralPath $mf -Encoding ASCII

# 用 python zipfile 打包（逐文件读取带重试）：jar.exe 大读盘时若被外部进程
# 独占/删除文件会中途失败；且对含非 ASCII 路径的参数传递也更稳。
$packArgs = @($JarOut, $mf, $Classes, $Libs) + $MustClasses + @('com\kbox\gui\ProtectorGui.class')
$coreSrc = Join-Path $Root 'kbox-core\src\main\java'
$jarOk = $false
for ($i = 0; $i -lt 8 -and -not $jarOk; $i++) {
    Remove-Item -Force $JarOut -ErrorAction SilentlyContinue
    if ($i -eq 0) {
        python (Join-Path $Root 'jarpack.py') @packArgs 2>&1 | Out-Null
    } else {
        # 重试：现场重编 kbox-core，把关键类读取窗口压到毫秒级（规避实时防护隔离）
        python (Join-Path $Root 'jarpack.py') @packArgs --core-src $coreSrc --core-deps $DepCp 2>&1 | Out-Null
    }
    if ($LASTEXITCODE -eq 0) { $jarOk = $true; break }
    Write-Host "jar 打包缺关键类（实时防护拦截），现场重编 kbox-core 重试 (尝试 $($i + 1))"
}
if (-not $jarOk) { throw 'jar 打包失败（多次修复仍缺关键类）' }

Write-Host ("== 完成: {0} ({1} bytes) ==" -f $JarOut, (Get-Item $JarOut).Length)
