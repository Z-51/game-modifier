#Requires -Version 5.1
<#
================================================================================
 game-modifier 一键安装脚本 (Windows PowerShell 5.1+)
================================================================================

 用法示例：

   # 完整安装（默认，等价于 pip install ".[all]"）
   .\install.ps1

   # 最小安装（仅核心依赖 psutil / PyYAML / tomli）
   .\install.ps1 -Mode minimal

   # 安装 MCP 服务器支持
   .\install.ps1 -Mode mcp

   # 开发模式（可编辑安装 + pytest / pyflakes）
   .\install.ps1 -Mode dev

   # 跳过虚拟环境（当前已在 venv 中，或想装进全局解释器）
   .\install.ps1 -SkipVenv

   # 指定 Python 解释器
   .\install.ps1 -PythonPath "C:\Python312\python.exe"

   # 强制重装（跳过覆盖确认，附带 --force-reinstall）
   .\install.ps1 -Force

   # 只演练不实际安装（打印将要执行的命令）
   .\install.ps1 -DryRun

 若 PowerShell 拒绝执行本脚本，改用：
   powershell.exe -ExecutionPolicy Bypass -File .\install.ps1
 或直接双击 / 运行 install.bat。

 参数说明：
   -Mode        安装模式：minimal | mcp | full | dev（默认 full）
   -SkipVenv    不创建 .venv，直接装进当前 Python 环境
   -Force       已安装时不再询问，直接强制重装
   -PythonPath  显式指定 python.exe 路径
   -DryRun      演练模式，不写入任何环境
================================================================================
#>

param(
    [ValidateSet("minimal", "mcp", "full", "dev")]
    [string]$Mode = "full",
    [switch]$SkipVenv,
    [switch]$Force,
    [string]$PythonPath,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# ------------------------------------------------------------------ 全局常量 --
$Script:ProjectRoot  = $PSScriptRoot
$Script:VenvDir      = Join-Path $Script:ProjectRoot ".venv"
$Script:TotalSteps   = 7
$Script:MinPython    = [Version]"3.10"
$Script:PackageName  = "game-modifier"
$Script:PythonDlUrl  = "https://www.python.org/downloads/windows/"

# 各安装模式对应的 pip 参数（数组形式传递，避免 PowerShell 方括号解析问题）
$Script:ModeSpec = @{
    minimal = @{ Args = @("install", ".");                  Desc = "最小安装 — 仅核心依赖（psutil / PyYAML / tomli）" }
    mcp     = @{ Args = @("install", ".[mcp]");             Desc = "MCP 安装 — 核心依赖 + MCP 服务器" }
    full    = @{ Args = @("install", ".[all]");             Desc = "完整安装 — 核心依赖 + r2pipe + mcp + pytest" }
    dev     = @{ Args = @("install", "-e", ".[dev]");       Desc = "开发安装 — 可编辑模式 + pytest + pyflakes" }
}

# ------------------------------------------------------------------ 输出辅助 --
function Write-Banner {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  game-modifier 安装程序  ——  单机游戏内存修改器 CLI 插件" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([int]$Index, [string]$Message)
    Write-Host ""
    Write-Host ("[{0}/{1}] {2}" -f $Index, $Script:TotalSteps, $Message) -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host ("  " + [char]0x2713 + " $Message") -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    Write-Host ("  " + [char]0x2717 + " $Message") -ForegroundColor Red
}

function Write-Warn {
    param([string]$Message)
    Write-Host ("  " + [char]0x26A0 + " $Message") -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor Gray
}

# ------------------------------------------------------------ 原生命令封装 --
# 调用外部程序并检查退出码；-Capture 时捕获输出而不直接打印。
function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [string[]]$Arguments = @(),
        [switch]$Capture,
        [switch]$AllowFailure
    )

    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"    # 原生程序写 stderr 不应视为终止错误
    try {
        if ($Capture) {
            $output = & $Exe @Arguments 2>&1 | Out-String
        }
        else {
            & $Exe @Arguments 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
            $output = ""
        }
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previous
    }

    if ($code -ne 0 -and -not $AllowFailure) {
        if ($Capture -and $output.Trim()) { Write-Info $output.Trim() }
        throw "命令执行失败（退出码 $code）：$Exe $($Arguments -join ' ')"
    }

    return [pscustomobject]@{
        ExitCode = $code
        Output   = $output.Trim()
        Success  = ($code -eq 0)
    }
}

# ---------------------------------------------------------------- 环境检测 --
function Test-Administrator {
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Show-SystemInfo {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        Write-Ok "操作系统：$($os.Caption) (Build $($os.BuildNumber))"
        if ([Environment]::OSVersion.Version.Major -lt 10) {
            Write-Warn "本工具的支持目标为 Windows 10 / 11，更早版本未经测试"
        }
    }
    catch {
        Write-Warn "无法读取操作系统信息：$($_.Exception.Message)"
    }
    Write-Ok "PowerShell 版本：$($PSVersionTable.PSVersion)"
    Write-Ok "系统架构：$env:PROCESSOR_ARCHITECTURE"
}

# 返回候选 python.exe 的绝对路径列表（按优先级）
function Get-PythonCandidates {
    $candidates = New-Object System.Collections.Generic.List[string]

    if ($PythonPath) {
        if (-not (Test-Path -LiteralPath $PythonPath)) {
            throw "指定的 Python 路径不存在：$PythonPath"
        }
        $candidates.Add((Resolve-Path -LiteralPath $PythonPath).Path)
        return $candidates
    }

    # 已处于虚拟环境中时优先复用它
    if ($SkipVenv -and $env:VIRTUAL_ENV) {
        $venvPython = Join-Path $env:VIRTUAL_ENV "Scripts\python.exe"
        if (Test-Path -LiteralPath $venvPython) { $candidates.Add($venvPython) }
    }

    foreach ($name in @("python.exe", "python3.exe")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { $candidates.Add($cmd.Source) }
    }

    # py 启动器：解析出真实解释器路径
    if (Get-Command "py.exe" -ErrorAction SilentlyContinue) {
        $probe = Invoke-Native -Exe "py.exe" -Arguments @("-3", "-c", "import sys;print(sys.executable)") -Capture -AllowFailure
        if ($probe.Success -and $probe.Output) { $candidates.Add($probe.Output) }
    }

    return ($candidates | Select-Object -Unique)
}

# 解释器对应的入口点脚本目录（venv 下为 .venv\Scripts，全局安装下为 Python\Scripts）
function Get-ScriptsDir {
    param([string]$Exe)
    $probe = Invoke-Native -Exe $Exe `
        -Arguments @("-c", "import sysconfig;print(sysconfig.get_path('scripts'))") -Capture -AllowFailure
    if ($probe.Success -and $probe.Output) { return (($probe.Output -split "`n")[0]).Trim() }
    return (Split-Path -Parent $Exe)
}

function Get-PythonVersion {
    param([string]$Exe)
    $probe = Invoke-Native -Exe $Exe `
        -Arguments @("-c", "import sys;print('%d.%d.%d' % sys.version_info[:3])") -Capture -AllowFailure
    if (-not $probe.Success) { return $null }
    try   { return [Version]$probe.Output }
    catch { return $null }
}

# 选出满足版本要求的解释器
function Resolve-PythonExe {
    $candidates = Get-PythonCandidates
    if (-not $candidates -or $candidates.Count -eq 0) {
        Write-Fail "未检测到 Python 解释器"
        Write-Info "请先安装 Python $($Script:MinPython) 或更高版本：$Script:PythonDlUrl"
        Write-Info "安装时请勾选 “Add python.exe to PATH”，或用 -PythonPath 指定解释器路径"
        throw "Python 未找到"
    }

    $rejected = @()
    foreach ($exe in $candidates) {
        $version = Get-PythonVersion -Exe $exe
        if (-not $version) {
            $rejected += "$exe（无法获取版本）"
            continue
        }
        if ($version -lt $Script:MinPython) {
            $rejected += "$exe（$version，低于 $($Script:MinPython)）"
            continue
        }
        Write-Ok "Python $version — $exe"
        return $exe
    }

    Write-Fail "已找到 Python，但没有满足 >= $($Script:MinPython) 的版本"
    foreach ($item in $rejected) { Write-Info "跳过：$item" }
    Write-Info "下载新版 Python：$Script:PythonDlUrl"
    throw "Python 版本不满足要求"
}

function Test-PipAvailable {
    param([string]$Exe)
    $probe = Invoke-Native -Exe $Exe -Arguments @("-m", "pip", "--version") -Capture -AllowFailure
    if (-not $probe.Success) {
        Write-Fail "该 Python 环境中 pip 不可用"
        Write-Info "尝试修复：`"$Exe`" -m ensurepip --upgrade"
        throw "pip 不可用"
    }
    Write-Ok "pip 可用：$($probe.Output.Split("`n")[0])"
}

# 检测是否已安装本包，必要时询问是否覆盖
function Test-ExistingInstall {
    param([string]$Exe)
    $probe = Invoke-Native -Exe $Exe -Arguments @("-m", "pip", "show", $Script:PackageName) -Capture -AllowFailure
    if (-not $probe.Success) {
        Write-Ok "未检测到已安装的 $Script:PackageName（全新安装）"
        return $false
    }

    $installed = ($probe.Output -split "`n" | Where-Object { $_ -match '^Version:' }) -replace '^Version:\s*', ''
    Write-Warn "检测到已安装 $Script:PackageName $installed"

    if ($Force -or $DryRun) {
        Write-Info "已指定 -Force（或 -DryRun），将直接覆盖安装"
        return $true
    }

    $answer = Read-Host "  是否覆盖安装？[Y/n]"
    if ($answer -and $answer.Trim().ToLower() -notin @("y", "yes")) {
        throw "用户取消安装"
    }
    return $true
}

# ------------------------------------------------------------ 虚拟环境处理 --
function New-VirtualEnvironment {
    param([string]$Exe)

    $venvPython = Join-Path $Script:VenvDir "Scripts\python.exe"
    if (Test-Path -LiteralPath $venvPython) {
        Write-Ok "复用已存在的虚拟环境：$Script:VenvDir"
        return $venvPython
    }

    if ($DryRun) {
        Write-Info "[DryRun] `"$Exe`" -m venv `"$Script:VenvDir`""
        return $Exe
    }

    try {
        Invoke-Native -Exe $Exe -Arguments @("-m", "venv", $Script:VenvDir) | Out-Null
    }
    catch {
        Write-Fail "虚拟环境创建失败：$($_.Exception.Message)"
        Write-Info "常见原因：目录无写入权限、路径被安全软件锁定、磁盘空间不足"
        Write-Info "可尝试：以管理员身份运行本脚本，或改用 -SkipVenv 装入现有环境"
        throw
    }

    if (-not (Test-Path -LiteralPath $venvPython)) {
        throw "虚拟环境目录已生成，但缺少 Scripts\python.exe：$Script:VenvDir"
    }
    Write-Ok "虚拟环境已创建：$Script:VenvDir"
    return $venvPython
}

# 通过环境变量激活，避免 Activate.ps1 受执行策略限制
function Enable-VirtualEnvironment {
    param([string]$VenvPath)

    $scripts = Join-Path $VenvPath "Scripts"
    if (-not (Test-Path -LiteralPath $scripts)) {
        Write-Warn "未找到 $scripts，跳过激活"
        return
    }

    $env:VIRTUAL_ENV = $VenvPath
    $env:PATH        = "$scripts;$env:PATH"
    Remove-Item Env:\PYTHONHOME -ErrorAction SilentlyContinue
    Write-Ok "虚拟环境已激活（当前会话）：$VenvPath"
    Write-Info "新开终端后需重新激活：$scripts\Activate.ps1"
}

# ---------------------------------------------------------------- 安装步骤 --
function Update-Pip {
    param([string]$Exe)
    if ($DryRun) {
        Write-Info "[DryRun] `"$Exe`" -m pip install --upgrade pip"
        return
    }
    try {
        Invoke-Native -Exe $Exe -Arguments @("-m", "pip", "install", "--upgrade", "pip") | Out-Null
        $probe = Invoke-Native -Exe $Exe -Arguments @("-m", "pip", "--version") -Capture -AllowFailure
        Write-Ok "pip 已升级：$($probe.Output.Split("`n")[0])"
    }
    catch {
        Write-Warn "pip 升级失败，继续使用当前版本（$($_.Exception.Message)）"
    }
}

function Install-Project {
    param([string]$Exe, [bool]$Reinstall)

    $spec    = $Script:ModeSpec[$Mode]
    $pipArgs = @("-m", "pip") + $spec.Args
    if ($Reinstall -and $Force) { $pipArgs += "--force-reinstall" }

    Write-Info $spec.Desc
    if ($DryRun) {
        # 展示时给带方括号的参数加引号，保证可直接复粘到 PowerShell 执行
        $shown = $pipArgs | ForEach-Object { if ($_ -match '[\[\]]') { "`"$_`"" } else { $_ } }
        Write-Info "[DryRun] `"$Exe`" $($shown -join ' ')  (cwd: $Script:ProjectRoot)"
        return
    }

    Push-Location $Script:ProjectRoot
    try {
        Invoke-Native -Exe $Exe -Arguments $pipArgs | Out-Null
        Write-Ok "安装完成（模式：$Mode）"
    }
    catch {
        Write-Fail "pip 安装失败：$($_.Exception.Message)"
        Write-Info "常见解决方案："
        Write-Info "  1) 网络问题 —— 换用镜像：pip install -i https://pypi.tuna.tsinghua.edu.cn/simple ."
        Write-Info "  2) 依赖冲突 —— 使用干净虚拟环境（去掉 -SkipVenv 重新运行）"
        Write-Info "  3) 权限不足 —— 以管理员身份运行，或加 --user 手动安装"
        Write-Info "  4) mcp 与 fastapi/starlette 冲突 —— pip install --upgrade fastapi"
        throw
    }
    finally {
        Pop-Location
    }
}

# ---------------------------------------------------------------- 安装验证 --
function Test-Installation {
    param([string]$Exe)

    if ($DryRun) {
        Write-Info "[DryRun] 跳过安装验证"
        return $true
    }

    $checks = @(
        @{ Name = "CLI 入口 (game-modifier --version)"; Args = @("-m", "game_modifier", "--version"); Required = $true }
        @{ Name = "引擎检测模块 (Engines)";  Args = @("-c", "from game_modifier.engines import NWJS, RPG_MAKER, RENPY; print('Engines OK')");            Required = $true }
        @{ Name = "窗口标题附加 (Window)";   Args = @("-c", "from game_modifier.memory.process import find_by_window_title; print('Window OK')");        Required = $true }
        @{ Name = "存档修改模块 (SaveEdit)"; Args = @("-c", "from game_modifier.save_edit import detect_saves; print('SaveEdit OK')");                   Required = $true }
    )

    # MCP 仅在包含 mcp 依赖的模式下为必需；dev 模式不含 mcp，失败仅告警
    if ($Mode -in @("mcp", "full")) {
        $checks += @{ Name = "MCP 服务器 (MCP)"; Args = @("-c", "from game_modifier.mcp_server import build_server; print('MCP OK')"); Required = $true }
    }
    elseif ($Mode -eq "dev") {
        $checks += @{ Name = "MCP 服务器 (MCP, 可选)"; Args = @("-c", "from game_modifier.mcp_server import build_server; print('MCP OK')"); Required = $false }
    }

    $failed = @()
    foreach ($check in $checks) {
        $probe = Invoke-Native -Exe $Exe -Arguments $check.Args -Capture -AllowFailure
        if ($probe.Success) {
            $firstLine = ($probe.Output -split "`n")[0]
            Write-Ok "$($check.Name)：$firstLine"
        }
        elseif ($check.Required) {
            Write-Fail "$($check.Name) 验证失败"
            if ($probe.Output) {
                $tail = ($probe.Output -split "`n") | Select-Object -Last 3
                Write-Info ($tail -join " ")
            }
            $failed += $check.Name
        }
        else {
            Write-Warn "$($check.Name) 不可用（当前模式未安装 mcp，属预期行为）"
            Write-Info "需要 MCP 时执行：pip install `".[mcp]`""
        }
    }

    # 入口点可执行文件
    $scriptsDir = Get-ScriptsDir -Exe $Exe
    $cliExe     = Join-Path $scriptsDir "game-modifier.exe"
    if (Test-Path -LiteralPath $cliExe) {
        $probe = Invoke-Native -Exe $cliExe -Arguments @("--version") -Capture -AllowFailure
        if ($probe.Success) { Write-Ok "入口点可执行文件：$cliExe" }
        else { Write-Warn "入口点存在但执行失败：$cliExe" }
    }
    else {
        Write-Warn "未在 $scriptsDir 找到 game-modifier.exe，可用 python -m game_modifier 代替"
    }

    if ($failed.Count -gt 0) {
        Write-Fail "以下模块验证未通过：$($failed -join '、')"
        Write-Info "建议：确认安装日志无报错后重新运行；或用 -Force 强制重装"
        return $false
    }
    return $true
}

# ------------------------------------------------------------ 完成信息输出 --
function Show-Completion {
    param([string]$Exe, [bool]$UsedVenv)

    $version = "未知"
    if (-not $DryRun) {
        $probe = Invoke-Native -Exe $Exe -Arguments @("-m", "pip", "show", $Script:PackageName) -Capture -AllowFailure
        if ($probe.Success) {
            $version = ((($probe.Output -split "`n") | Where-Object { $_ -match '^Version:' }) -replace '^Version:\s*', '').Trim()
        }
    }
    $scriptsDir = Get-ScriptsDir -Exe $Exe

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "  安装完成！" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  安装信息" -ForegroundColor Cyan
    Write-Info "项目路径：$Script:ProjectRoot"
    Write-Info "安装模式：$Mode — $($Script:ModeSpec[$Mode].Desc)"
    Write-Info "包版本：  $Script:PackageName $version"
    Write-Info "解释器：  $Exe"
    if ($UsedVenv) { Write-Info "虚拟环境：$Script:VenvDir" }
    else           { Write-Info "虚拟环境：未使用（-SkipVenv）" }

    Write-Host ""
    Write-Host "  可用命令" -ForegroundColor Cyan
    Write-Info "game-modifier       — CLI 主程序（每条命令输出一行 JSON）"
    Write-Info "game-modifier-mcp   — MCP 服务器（供 Agent 结构化调用）"
    Write-Info "python -m game_modifier --version   — 绕过 PATH 的调用方式"

    Write-Host ""
    Write-Host "  下一步" -ForegroundColor Cyan
    if ($UsedVenv) {
        Write-Info "1. 新终端中激活环境：$Script:VenvDir\Scripts\Activate.ps1"
        Write-Info "   （若被执行策略拒绝：Set-ExecutionPolicy -Scope CurrentUser RemoteSigned）"
    }
    else {
        Write-Info "1. 确认 Scripts 目录在 PATH 中：$scriptsDir"
    }
    Write-Info "2. 附加游戏进程需要 SeDebugPrivilege —— 请以管理员身份运行终端"
    Write-Info "3. 检查外部逆向工具：game-modifier toolchain detect"
    if ($Mode -in @("mcp", "full", "dev")) {
        Write-Info "4. 配置 MCP：Claude Code 直接读取仓库内 .mcp.json；"
        Write-Info "   Codex CLI 在 ~/.codex/config.toml 添加 [mcp_servers.game-modifier]"
        Write-Info "   command = `"$scriptsDir\game-modifier-mcp.exe`""
    }
    Write-Info "5. 文档：USER_MANUAL.md（命令参考）、AI_AGENT_GUIDE.md（Agent 集成）"

    if ($Mode -eq "dev") {
        Write-Host ""
        Write-Host "  开发模式提示" -ForegroundColor Cyan
        Write-Info "运行测试：  `"$Exe`" -m pytest tests/"
        Write-Info "静态检查：  `"$Exe`" -m pyflakes src/ tests/"
        Write-Info "可编辑安装下修改 src/ 代码立即生效，无需重装"
    }

    Write-Host ""
    Write-Warn "仅适用于单机 / 离线游戏；检测到反作弊时工具会拒绝附加进程。"
    Write-Host ""
}

# -------------------------------------------------------------------- 主流程 --
function Invoke-Install {
    Write-Banner
    Write-Host "  安装模式：$Mode — $($Script:ModeSpec[$Mode].Desc)" -ForegroundColor White
    Write-Host "  项目路径：$Script:ProjectRoot" -ForegroundColor White
    if ($SkipVenv) { Write-Host "  虚拟环境：跳过（-SkipVenv）" -ForegroundColor White }
    if ($DryRun)   { Write-Host "  演练模式：已开启，不会修改任何环境（-DryRun）" -ForegroundColor Yellow }

    # [1/7] 环境检测
    Write-Step 1 "环境检测"
    Show-SystemInfo
    if (Test-Administrator) {
        Write-Ok "当前以管理员权限运行"
    }
    else {
        Write-Warn "当前非管理员权限：安装本身不受影响，但附加游戏进程时需要管理员终端"
    }
    if (-not (Test-Path -LiteralPath (Join-Path $Script:ProjectRoot "pyproject.toml"))) {
        throw "未在 $Script:ProjectRoot 找到 pyproject.toml，请在项目根目录运行本脚本"
    }
    Write-Ok "已定位项目配置：pyproject.toml"

    $systemPython = Resolve-PythonExe
    Test-PipAvailable -Exe $systemPython

    # [2/7] 创建虚拟环境
    Write-Step 2 "创建虚拟环境"
    $usedVenv = $false
    $python   = $systemPython
    if ($SkipVenv) {
        Write-Warn "已指定 -SkipVenv，将安装到当前 Python 环境：$systemPython"
    }
    else {
        $python   = New-VirtualEnvironment -Exe $systemPython
        $usedVenv = -not $DryRun -or (Test-Path -LiteralPath (Join-Path $Script:VenvDir "Scripts\python.exe"))
    }

    # [3/7] 激活虚拟环境
    Write-Step 3 "激活虚拟环境"
    if ($usedVenv) {
        Enable-VirtualEnvironment -VenvPath $Script:VenvDir
    }
    else {
        Write-Info "无需激活（未使用虚拟环境）"
    }

    # 覆盖确认放在解释器确定之后，避免误判其它环境
    $reinstall = Test-ExistingInstall -Exe $python

    # [4/7] 升级 pip
    Write-Step 4 "升级 pip"
    Update-Pip -Exe $python

    # [5/7] 安装项目
    Write-Step 5 "安装 $Script:PackageName"
    Install-Project -Exe $python -Reinstall $reinstall

    # [6/7] 安装验证
    Write-Step 6 "安装验证"
    $verified = Test-Installation -Exe $python

    # [7/7] 完成
    Write-Step 7 "完成"
    if (-not $verified) {
        throw "安装已执行，但部分模块验证失败"
    }
    Show-Completion -Exe $python -UsedVenv $usedVenv
    return 0
}

try {
    $exitCode = Invoke-Install
    exit $exitCode
}
catch {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Red
    Write-Fail "安装中断：$($_.Exception.Message)"
    Write-Host "================================================================" -ForegroundColor Red
    Write-Info "排查建议："
    Write-Info ("  - 查看上方最后一条 " + [char]0x2717 + " 标记定位失败环节")
    Write-Info "  - 以管理员身份重新运行：powershell -ExecutionPolicy Bypass -File install.ps1"
    Write-Info "  - 详细安装说明见 INSTALL_GUIDE.md 第 6 节“常见安装问题”"
    Write-Host ""
    exit 1
}
