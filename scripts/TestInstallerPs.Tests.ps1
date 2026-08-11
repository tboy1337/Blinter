#Requires -Version 5.1
BeforeAll {
    . (Join-Path $PSScriptRoot 'InstallerPs.Helpers.ps1')
    $script:ScriptsRoot = $PSScriptRoot
    $script:InstallerPsRoot = Join-Path $PSScriptRoot 'installer_ps'
    $script:AnalyzerSettings = Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'
}

Describe 'Installer batch PowerShell parity' {
    It 'matches fixture content for each write_*_script block' {
        $pairs = Get-InstallerPsParityPairs -ScriptsRoot $script:ScriptsRoot -InstallerPsRoot $script:InstallerPsRoot
        $pairs.Count | Should -Be 5

        foreach ($pair in $pairs) {
            $normalizedExtracted = Normalize-InstallerPsText -Content $pair.Extracted
            $normalizedFixture = Normalize-InstallerPsText -Content $pair.FixtureBody
            $normalizedExtracted | Should -Be $normalizedFixture `
                -Because "parity failed for $($pair.CmdFile):$($pair.Label) -> $($pair.Fixture)"
        }
    }
}

Describe 'Installer PowerShell PSScriptAnalyzer' {
    It 'reports no warnings for installer fixtures and smoke scripts' {
        if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
            Set-ItResult -Inconclusive -Because 'PSScriptAnalyzer is not installed'
            return
        }

        $paths = Get-PowerShellAnalyzePaths -ScriptsRoot $script:ScriptsRoot
        $issues = Invoke-InstallerPsScriptAnalyzer -Paths $paths -SettingsPath $script:AnalyzerSettings
        if ($issues) {
            $formatted = $issues | Format-Table RuleName, ScriptName, Line, Message -Wrap | Out-String
            throw "PSScriptAnalyzer findings:`n$formatted"
        }
    }
}

Describe 'Get-LatestBlinterRelease.ps1' {
    It 'outputs NOT_FOUND when no release is available' {
        $fixturePath = Join-Path $script:InstallerPsRoot 'Get-LatestBlinterRelease.ps1'
        Mock Invoke-RestMethod { return @() }

        $output = & $fixturePath
        $LASTEXITCODE | Should -Be 0
        $output | Should -Be 'NOT_FOUND'
    }

    It 'outputs URL and tag when a matching asset exists' {
        $fixturePath = Join-Path $script:InstallerPsRoot 'Get-LatestBlinterRelease.ps1'
        Mock Invoke-RestMethod {
            return @(
                [PSCustomObject]@{
                    prerelease = $false
                    draft      = $false
                    tag_name   = 'v1.1.6'
                    assets     = @(
                        [PSCustomObject]@{
                            name                 = 'Blinter-v1.1.6.zip'
                            browser_download_url = 'https://example.com/Blinter-v1.1.6.zip'
                        }
                    )
                }
            )
        }

        $output = & $fixturePath
        $LASTEXITCODE | Should -Be 0
        $output | Should -Be 'https://example.com/Blinter-v1.1.6.zip v1.1.6'
    }
}

Describe 'Update-BlinterUserPath.ps1' {
    It 'builds a PATH value that appends the bin directory' {
        $binPath = 'C:\Test\Blinter\bin'
        $path = 'C:\Existing'
        if (-not $path) { $path = '' }
        if ($path -notlike "*$binPath*") {
            if (-not $path) {
                $newPath = $binPath
            }
            else {
                $newPath = $path.TrimEnd(';') + ';' + $binPath
            }
        }
        $newPath | Should -Be 'C:\Existing;C:\Test\Blinter\bin'
    }
}

Describe 'Remove-BlinterUserPath.ps1' {
    It 'removes the bin path from the user PATH' {
        $binPath = 'C:\Test\Blinter\bin'
        $path = 'C:\Alpha;C:\Test\Blinter\bin;C:\Beta'
        $pathArray = $path -split ';' | Where-Object { $_ -ne '' -and $_ -ne $binPath }
        $newPath = $pathArray -join ';'
        $newPath | Should -Be 'C:\Alpha;C:\Beta'
    }
}
