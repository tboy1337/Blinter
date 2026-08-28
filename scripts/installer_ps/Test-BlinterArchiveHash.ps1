#Requires -Version 5.1
$expected = '__BLINTER_SHA256__'
$actual = (Get-FileHash -LiteralPath '__BLINTER_TEMP__.zip' -Algorithm SHA256).Hash.ToLowerInvariant()
$normalized = $expected.ToLowerInvariant() -replace '^sha256:', ''
if ($actual -ne $normalized) { Write-Output 'MISMATCH'; exit 1 }
Write-Output 'OK'
