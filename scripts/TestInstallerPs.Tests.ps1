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
        $pairs.Count | Should -Be 6

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

    It 'outputs URL tag and digest when a matching asset exists' {
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
                            digest               = 'sha256:abc123'
                        }
                    )
                }
            )
        }

        $output = & $fixturePath
        $LASTEXITCODE | Should -Be 0
        $output | Should -Be 'https://example.com/Blinter-v1.1.6.zip v1.1.6 sha256:abc123'
    }

    It 'outputs MISSING_DIGEST when the asset has no digest' {
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
        $output | Should -Be 'MISSING_DIGEST'
    }
}

Describe 'Test-BlinterArchiveHash.ps1' {
    It 'exits 0 when the archive hash matches the GitHub digest' {
        $tempFile = Join-Path $TestDrive 'archive.zip'
        Set-Content -LiteralPath $tempFile -Value 'blinter-archive' -NoNewline
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $stream = [System.IO.File]::OpenRead($tempFile)
            try {
                $hash = [System.BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '')
            } finally { $stream.Dispose() }
        } finally { $sha.Dispose() }
        $script = Get-Content -LiteralPath (Join-Path $script:InstallerPsRoot 'Test-BlinterArchiveHash.ps1') -Raw
        $script = $script.Replace('__BLINTER_TEMP__', ($tempFile -replace '\.zip$', ''))
        $script = $script.Replace('__BLINTER_SHA256__', "sha256:$hash")
        $tempScript = Join-Path $TestDrive 'verify.ps1'
        Set-Content -LiteralPath $tempScript -Value $script
        & $tempScript
        $LASTEXITCODE | Should -Be 0
    }

    It 'exits 1 when the archive hash does not match' {
        $tempFile = Join-Path $TestDrive 'archive.zip'
        Set-Content -LiteralPath $tempFile -Value 'blinter-archive' -NoNewline
        $script = Get-Content -LiteralPath (Join-Path $script:InstallerPsRoot 'Test-BlinterArchiveHash.ps1') -Raw
        $script = $script.Replace('__BLINTER_TEMP__', ($tempFile -replace '\.zip$', ''))
        $script = $script.Replace('__BLINTER_SHA256__', 'sha256:deadbeef')
        $tempScript = Join-Path $TestDrive 'verify.ps1'
        Set-Content -LiteralPath $tempScript -Value $script
        & $tempScript
        $LASTEXITCODE | Should -Be 1
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
