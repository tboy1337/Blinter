#Requires -Version 5.1
<#
.SYNOPSIS
    Run PSScriptAnalyzer and Pester checks for Blinter smoke-test scripts.

.DESCRIPTION
    Shared by scripts/verify.py and GitHub Actions Windows jobs.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

$ErrorActionPreference = 'Stop'

$helpers = Join-Path $RepoRoot 'scripts\TestExeSmoke.Helpers.ps1'
$runner = Join-Path $RepoRoot 'scripts\test_exe_smoke.ps1'
$analyzerSettings = Join-Path $RepoRoot 'scripts\PSScriptAnalyzerSettings.psd1'
$pesterTest = Join-Path $RepoRoot 'scripts\TestExeSmoke.Tests.ps1'

foreach ($moduleName in @('PSScriptAnalyzer', 'Pester')) {
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Install-Module -Name $moduleName -Force -Scope CurrentUser -AllowClobber -Repository PSGallery
    }
}

$issues = @()
foreach ($path in @($helpers, $runner)) {
    $issues += Invoke-ScriptAnalyzer -Path $path -Settings $analyzerSettings -Severity Warning
}
if ($issues) {
    $issues | Format-Table -AutoSize
    exit 1
}

Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop
$config = New-PesterConfiguration
$config.Run.Path = $pesterTest
$config.Run.PassThru = $true
$config.Run.Exit = $true
Invoke-Pester -Configuration $config | Out-Null
