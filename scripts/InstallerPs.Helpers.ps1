#Requires -Version 5.1
Set-StrictMode -Version Latest

function Get-InstallerPsScriptMap {
    return [ordered]@{
        'install_blinter.cmd' = [ordered]@{
            'write_get_release_script' = @{
                Fixture      = 'Get-LatestBlinterRelease.ps1'
                Placeholders = @{}
            }
            'write_file_size_script' = @{
                Fixture      = 'Get-DownloadedFileSize.ps1'
                Placeholders = @{ '%BLINTER_TEMP%' = '__BLINTER_TEMP__' }
            }
            'write_hash_verify_script' = @{
                Fixture      = 'Test-BlinterArchiveHash.ps1'
                Placeholders = @{
                    '%BLINTER_TEMP%'   = '__BLINTER_TEMP__'
                    '%BLINTER_SHA256%' = '__BLINTER_SHA256__'
                }
            }
            'write_expand_script' = @{
                Fixture      = 'Expand-BlinterArchive.ps1'
                Placeholders = @{ '%BLINTER_TEMP%' = '__BLINTER_TEMP__' }
            }
            'write_update_path_script' = @{
                Fixture      = 'Update-BlinterUserPath.ps1'
                Placeholders = @{ '%BLINTER_BIN%' = '__BLINTER_BIN__' }
            }
        }
        'uninstall_blinter.cmd' = [ordered]@{
            'write_remove_path_script' = @{
                Fixture      = 'Remove-BlinterUserPath.ps1'
                Placeholders = @{ '%BLINTER_BIN%' = '__BLINTER_BIN__' }
            }
        }
    }
}

function ConvertFrom-BatchEchoEscape {
    param([string]$Line)

    $result = $Line
    $result = $result -replace '\^\|', '|'
    $result = $result -replace '\^\)', ')'
    $result = $result -replace '\^\>', '>'
    $result = $result -replace '\^&', '&'
    return $result
}

function Get-BatchEchoScriptContent {
    param(
        [string]$CmdFilePath,
        [string]$LabelName
    )

    if (-not (Test-Path -LiteralPath $CmdFilePath)) {
        throw "Batch file not found: $CmdFilePath"
    }

    $lines = Get-Content -LiteralPath $CmdFilePath
    $labelPattern = "^:$([regex]::Escape($LabelName))\s*$"
    $startIndex = -1
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ($lines[$index] -match $labelPattern) {
            $startIndex = $index + 1
            break
        }
    }

    if ($startIndex -lt 0) {
        throw "Label :$LabelName not found in $CmdFilePath"
    }

    if ($lines[$startIndex].Trim() -ne '(') {
        throw "Expected '(' after :$LabelName in $CmdFilePath"
    }

    $echoLines = [System.Collections.Generic.List[string]]::new()
    for ($index = $startIndex + 1; $index -lt $lines.Count; $index++) {
        $line = $lines[$index]
        if ($line.Trim() -match '^\)\s*>') {
            break
        }

        $trimmed = $line.TrimStart()
        if ($trimmed -match '^echo (.*)$') {
            $echoLines.Add((ConvertFrom-BatchEchoEscape -Line $Matches[1]))
        }
        elseif ($trimmed -eq ')') {
            break
        }
    }

    return ($echoLines -join "`r`n")
}

function Get-InstallerPsFixtureContent {
    param(
        [string]$InstallerPsRoot,
        [string]$FixtureName
    )

    $fixturePath = Join-Path $InstallerPsRoot $FixtureName
    if (-not (Test-Path -LiteralPath $fixturePath)) {
        throw "Fixture not found: $fixturePath"
    }

    $content = Get-Content -LiteralPath $fixturePath -Raw
  return $content.TrimEnd("`r", "`n")
}

function Apply-InstallerPsPlaceholders {
    param(
        [string]$Content,
        [hashtable]$Placeholders
    )

    $result = $Content
    foreach ($entry in $Placeholders.GetEnumerator()) {
        $result = $result.Replace($entry.Key, $entry.Value)
    }
    return $result
}

function Normalize-InstallerPsText {
    param([string]$Content)

    $normalized = $Content -replace "`r`n", "`n"
    $normalized = $normalized -replace "`r", "`n"
    return $normalized.TrimEnd("`n")
}

function Get-InstallerPsParityPairs {
    param(
        [string]$ScriptsRoot,
        [string]$InstallerPsRoot
    )

    $pairs = [System.Collections.Generic.List[object]]::new()
    $scriptMap = Get-InstallerPsScriptMap

    foreach ($cmdEntry in $scriptMap.GetEnumerator()) {
        $cmdPath = Join-Path $ScriptsRoot $cmdEntry.Key
        foreach ($labelEntry in $cmdEntry.Value.GetEnumerator()) {
            $config = $labelEntry.Value
            $extracted = Get-BatchEchoScriptContent -CmdFilePath $cmdPath -LabelName $labelEntry.Key
            $extracted = Apply-InstallerPsPlaceholders -Content $extracted -Placeholders $config.Placeholders
            $fixture = Get-InstallerPsFixtureContent -InstallerPsRoot $InstallerPsRoot -FixtureName $config.Fixture
            $fixtureBody = ($fixture -split "`n" | Select-Object -Skip 1) -join "`n"
            $pairs.Add([PSCustomObject]@{
                    CmdFile   = $cmdEntry.Key
                    Label     = $labelEntry.Key
                    Fixture   = $config.Fixture
                    Extracted = $extracted
                    FixtureBody = $fixtureBody.TrimEnd("`r", "`n")
                })
        }
    }

    return $pairs
}

function Get-InstallerPsFixturePaths {
    param([string]$InstallerPsRoot)

    return Get-ChildItem -LiteralPath $InstallerPsRoot -Filter '*.ps1' -File |
        Sort-Object Name |
        Select-Object -ExpandProperty FullName
}

function Get-PowerShellAnalyzePaths {
    param([string]$ScriptsRoot)

    $paths = @(
        (Join-Path $ScriptsRoot 'TestExeSmoke.Helpers.ps1'),
        (Join-Path $ScriptsRoot 'test_exe_smoke.ps1')
    )
    $paths += Get-InstallerPsFixturePaths -InstallerPsRoot (Join-Path $ScriptsRoot 'installer_ps')
    return $paths
}

function Invoke-InstallerPsScriptAnalyzer {
    param(
        [string[]]$Paths,
        [string]$SettingsPath
    )

    $issues = @()
    foreach ($path in $Paths) {
        $issues += Invoke-ScriptAnalyzer -Path $path -Settings $SettingsPath -Severity Warning
    }
    return $issues
}
