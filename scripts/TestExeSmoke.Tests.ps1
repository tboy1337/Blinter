#Requires -Version 5.1
BeforeAll {
    . (Join-Path $PSScriptRoot "TestExeSmoke.Helpers.ps1")
}

Describe "Format-CliArgument" {
    It "returns an empty string for no arguments" {
        Format-CliArgument -CliArgs @() | Should -Be ""
    }

    It "joins simple tokens" {
        Format-CliArgument -CliArgs @("one", "two") | Should -Be "one two"
    }

    It "quotes tokens containing spaces" {
        Format-CliArgument -CliArgs @("has space") | Should -Be '"has space"'
    }

    It "escapes embedded double quotes" {
        Format-CliArgument -CliArgs @('say "hi"') | Should -Be '"say ""hi"""'
    }
}

Describe "Test-NoRuntimeCrash" {
    It "passes for normal output" {
        { Test-NoRuntimeCrash -Output "all good" } | Should -Not -Throw
    }

    It "throws when a traceback is present" {
        { Test-NoRuntimeCrash -Output "Traceback (most recent call last):" } | Should -Throw
    }

    It "throws when ModuleNotFoundError is present" {
        { Test-NoRuntimeCrash -Output "ModuleNotFoundError: no module" } | Should -Throw
    }

    It "throws when ImportError is present" {
        { Test-NoRuntimeCrash -Output "ImportError: failed" } | Should -Throw
    }
}

Describe "Test-LintExitCode" {
    It "accepts exit code 0" {
        { Test-LintExitCode -ExitCode 0 } | Should -Not -Throw
    }

    It "accepts exit code 1" {
        { Test-LintExitCode -ExitCode 1 } | Should -Not -Throw
    }

    It "rejects other exit codes" {
        { Test-LintExitCode -ExitCode 2 } | Should -Throw "unexpected exit code 2"
    }
}

Describe "Get-JsonReport" {
    It "parses valid JSON from stdout" {
        $report = Get-JsonReport -Stdout '{"target":"sample.bat","issues":[]}'
        $report.target | Should -Be "sample.bat"
        $report.issues.Count | Should -Be 0
    }
}

Describe "Get-IssueRuleCode" {
    It "returns issue codes in order" {
        $report = [PSCustomObject]@{
            issues = @(
                [PSCustomObject]@{ code = "E001" }
                [PSCustomObject]@{ code = "S001" }
            )
        }
        Get-IssueRuleCode -Report $report | Should -Be @("E001", "S001")
    }
}

Describe "Invoke-BlinterProcess" {
    It "runs a child process and captures stdout" {
        $comspec = $env:ComSpec
        if (-not $comspec) {
            Set-ItResult -Inconclusive -Because "ComSpec is not set"
            return
        }

        $result = Invoke-BlinterProcess -Binary $comspec -CliArgs @(
            "/c", "echo hi"
        ) -WorkingDirectory $TestDrive
        $result.ExitCode | Should -Be 0
        $result.Stdout.Trim() | Should -Be "hi"
    }
}

Describe "New-ExeSmokeFixtureRoot" {
    It "creates expected fixture files without a UTF-8 BOM on blinter.ini" {
        $fixtureRoot = New-ExeSmokeFixtureRoot
        try {
            Test-Path -LiteralPath (Join-Path $fixtureRoot "sample.bat") | Should -Be $true
            Test-Path -LiteralPath (Join-Path $fixtureRoot "utf16.bat") | Should -Be $true
            Test-Path -LiteralPath (Join-Path $fixtureRoot "blinter.ini") | Should -Be $true

            $iniBytes = [System.IO.File]::ReadAllBytes((Join-Path $fixtureRoot "blinter.ini"))
            $iniBytes[0] | Should -Not -Be 0xEF
            $iniBytes[1] | Should -Not -Be 0xBB
            $iniBytes[2] | Should -Not -Be 0xBF
        }
        finally {
            if (Test-Path -LiteralPath $fixtureRoot) {
                Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
            }
        }
    }
}

Describe "Invoke-SmokeTest" {
    It "tracks passed and failed smoke cases" {
        Initialize-SmokeTestState
        Invoke-SmokeTest "passing case" { $true | Out-Null }
        Invoke-SmokeTest "failing case" { throw "boom" }

        $state = Get-SmokeTestState
        $state.Passed | Should -Be 1
        $state.Total | Should -Be 2
        $state.Failures.Count | Should -Be 1
        $state.Failures[0] | Should -Match "failing case"
    }
}
