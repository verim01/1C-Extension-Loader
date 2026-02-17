[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Log {
    param(
        [string]$Path,
        [string]$Level,
        [string]$Message
    )

    $line = "{0}`t{1}`t{2}" -f ([DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss.fff")), $Level, $Message
    Add-Content -LiteralPath $Path -Value $line -Encoding UTF8
}

function Resolve-RequiredPath {
    param(
        [string]$PathValue,
        [string]$FieldName
    )

    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        throw "Required config field is empty: $FieldName"
    }

    return [System.IO.Path]::GetFullPath($PathValue)
}

function Invoke-IbcmdStep {
    param(
        [string]$IbcmdExePath,
        [string[]]$Arguments,
        [string]$LogFile,
        [string]$StepName,
        [System.Security.SecureString]$IbPassword
    )

    $plainPass = $null
    if ($null -ne $IbPassword -and $IbPassword.Length -gt 0) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($IbPassword)
        try {
            $plainPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    $safeArgs = @()
    foreach ($arg in $Arguments) {
        if (-not [string]::IsNullOrWhiteSpace($plainPass) -and $arg -eq $plainPass) {
            $safeArgs += "***"
        }
        else {
            $safeArgs += $arg
        }
    }

    Write-Log -Path $LogFile -Level "INFO" -Message ("[{0}] START: {1} {2}" -f $StepName, $IbcmdExePath, ($safeArgs -join " "))
    $output = & $IbcmdExePath @Arguments 2>&1
    foreach ($line in $output) {
        Write-Log -Path $LogFile -Level "INFO" -Message ("[{0}] {1}" -f $StepName, [string]$line)
    }

    if ($LASTEXITCODE -ne 0) {
        throw "[${StepName}] ibcmd failed with exit code $LASTEXITCODE"
    }
}

try {
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
            $ConfigPath = Join-Path -Path $PSScriptRoot -ChildPath "runner.config.json"
        }
        else {
            $ConfigPath = Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Path) -ChildPath "runner.config.json"
        }
    }

    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw "Config file not found: $ConfigPath"
    }

    $cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json

    $infobaseDir = Resolve-RequiredPath -PathValue $cfg.infobase_dir -FieldName "infobase_dir"
    $extensionCfePath = Resolve-RequiredPath -PathValue $cfg.extension_cfe_path -FieldName "extension_cfe_path"
    $logDir = Resolve-RequiredPath -PathValue $cfg.log_dir -FieldName "log_dir"

    $ibcmdPath = ""
    if ($null -ne $cfg.ibcmd_exe_path -and -not [string]::IsNullOrWhiteSpace([string]$cfg.ibcmd_exe_path)) {
        $ibcmdPath = Resolve-RequiredPath -PathValue ([string]$cfg.ibcmd_exe_path) -FieldName "ibcmd_exe_path"
    }
    else {
        $oneCExePath = Resolve-RequiredPath -PathValue $cfg.onec_exe_path -FieldName "onec_exe_path"
        $ibcmdPath = Join-Path -Path (Split-Path -Parent $oneCExePath) -ChildPath "ibcmd.exe"
    }

    if (-not (Test-Path -LiteralPath $ibcmdPath -PathType Leaf)) {
        throw "ibcmd.exe not found: $ibcmdPath"
    }

    if (-not (Test-Path -LiteralPath $infobaseDir -PathType Container)) {
        throw "Infobase directory not found: $infobaseDir"
    }

    if (-not (Test-Path -LiteralPath $extensionCfePath -PathType Leaf)) {
        throw ".cfe file not found: $extensionCfePath"
    }

    $extensionName = ""
    if ($null -ne $cfg.extension_name -and -not [string]::IsNullOrWhiteSpace([string]$cfg.extension_name)) {
        $extensionName = [string]$cfg.extension_name
    }
    else {
        $extensionName = [System.IO.Path]::GetFileNameWithoutExtension($extensionCfePath)
    }

    $ibUser = ""
    if ($null -ne $cfg.ib_username) {
        $ibUser = [string]$cfg.ib_username
    }
    if ([string]::IsNullOrWhiteSpace($ibUser)) {
        throw "ib_username is required for ibcmd scenario"
    }

    $ibPass = ""
    if ($null -ne $cfg.ib_password) {
        $ibPass = [string]$cfg.ib_password
    }
    $ibPassSecure = $null
    if (-not [string]::IsNullOrWhiteSpace($ibPass)) {
        $ibPassSecure = ConvertTo-SecureString -String $ibPass -AsPlainText -Force
    }

    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    $stamp = [DateTime]::Now.ToString("yyyyMMdd_HHmmss")
    $logFile = Join-Path -Path $logDir -ChildPath ("ibcmd-load-extension_{0}.log" -f $stamp)

    Write-Log -Path $logFile -Level "INFO" -Message "ibcmd extension load flow started"
    Write-Log -Path $logFile -Level "INFO" -Message ("ibcmd: {0}" -f $ibcmdPath)
    Write-Log -Path $logFile -Level "INFO" -Message ("Infobase dir: {0}" -f $infobaseDir)
    Write-Log -Path $logFile -Level "INFO" -Message ("Extension name: {0}" -f $extensionName)
    Write-Log -Path $logFile -Level "INFO" -Message ("Extension file: {0}" -f $extensionCfePath)

    $loadArgs = @(
        "infobase",
        "--db-path=$infobaseDir",
        "config",
        "load",
        "-u", $ibUser,
        "-P", $ibPass,
        "--extension=$extensionName",
        $extensionCfePath
    )
    Invoke-IbcmdStep -IbcmdExePath $ibcmdPath -Arguments $loadArgs -LogFile $logFile -StepName "config-load" -IbPassword $ibPassSecure

    $updateArgs = @(
        "infobase",
        "--db-path=$infobaseDir",
        "config",
        "-u", $ibUser,
        "-P", $ibPass,
        "extension",
        "update",
        "--name=$extensionName",
        "--active=yes",
        "--safe-mode=no",
        "--unsafe-action-protection=no"
    )
    Invoke-IbcmdStep -IbcmdExePath $ibcmdPath -Arguments $updateArgs -LogFile $logFile -StepName "extension-update" -IbPassword $ibPassSecure

    $applyArgs = @(
        "infobase",
        "--db-path=$infobaseDir",
        "config",
        "-u", $ibUser,
        "-P", $ibPass,
        "apply",
        "--extension=$extensionName",
        "--force"
    )
    Invoke-IbcmdStep -IbcmdExePath $ibcmdPath -Arguments $applyArgs -LogFile $logFile -StepName "config-apply" -IbPassword $ibPassSecure

    [ordered]@{
        ok = $true
        status = "success"
        log_file = $logFile
        message = "ibcmd flow completed: load + extension update + apply"
    } | ConvertTo-Json -Depth 5
    exit 0
}
catch {
    [ordered]@{
        ok = $false
        status = "error"
        message = $_.Exception.Message
    } | ConvertTo-Json -Depth 5
    exit 1
}
