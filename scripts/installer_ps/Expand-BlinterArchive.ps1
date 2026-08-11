#Requires -Version 5.1
try {
    Expand-Archive -LiteralPath '__BLINTER_TEMP__.zip' -DestinationPath '__BLINTER_TEMP__' -Force
    exit 0
}
catch {
    Write-Host "ERROR: $_"
    exit 1
}
