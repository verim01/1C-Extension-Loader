[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ProfilesDir = "",
    [Parameter(Mandatory = $false)]
    [string]$DefaultProfileName = "default"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($ProfilesDir)) {
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $ProfilesDir = Join-Path -Path $PSScriptRoot -ChildPath "profiles"
    }
    else {
        $ProfilesDir = Join-Path -Path (Get-Location) -ChildPath "profiles"
    }
}

New-Item -ItemType Directory -Path $ProfilesDir -Force | Out-Null

Write-Host "=== MCP profile form ===" -ForegroundColor Cyan

$profileName = Read-Host "Profile name [$DefaultProfileName]"
if ([string]::IsNullOrWhiteSpace($profileName)) {
    $profileName = $DefaultProfileName
}

$infobaseDir = Read-Host "Infobase folder (e.g. H:\Rio-Santip4)"
$infobaseFilePath = Read-Host "Infobase file path (e.g. H:\Rio-Santip4\1Cv8.1CD)"
$ibUsername = Read-Host "IB username"
$ibPassword = Read-Host "IB password (plain text, will be saved to profile)"
$onecBinDir = Read-Host "1C bin folder (e.g. C:\Program Files\1cv8\8.3.xx.xxxx\bin)"
$logDir = Read-Host "Log folder (e.g. D:\projects\proj4\docs\automation\logs)"
$cfePath = Read-Host "Path to extension .cfe"

$extensionName = [System.IO.Path]::GetFileNameWithoutExtension($cfePath)
$overrideExtName = Read-Host "Extension name override [$extensionName]"
if (-not [string]::IsNullOrWhiteSpace($overrideExtName)) {
    $extensionName = $overrideExtName
}

$onecExePath = Join-Path -Path $onecBinDir -ChildPath "1cv8.exe"
$ibcmdExePath = Join-Path -Path $onecBinDir -ChildPath "ibcmd.exe"
$lockFilePath = Join-Path -Path (Split-Path -Parent $logDir) -ChildPath ".run.lock"

$profile = [ordered]@{
    name = $profileName
    infobase_dir = $infobaseDir
    infobase_file_path = $infobaseFilePath
    ib_username = $ibUsername
    ib_password = $ibPassword
    ibcmd_exe_path = $ibcmdExePath
    onec_exe_path = $onecExePath
    log_dir = $logDir
    timeout_sec = 900
    lock_file_path = $lockFilePath
    extensions = @(
        [ordered]@{
            name = $extensionName
            cfe_path = $cfePath
        }
    )
}

$targetFile = Join-Path -Path $ProfilesDir -ChildPath ($profileName + ".json")
$json = $profile | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText($targetFile, $json, [System.Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "Profile saved:" -ForegroundColor Green
Write-Host $targetFile
Write-Host ""
Write-Host "Next step: set this profile as default in host.config.json if needed."
