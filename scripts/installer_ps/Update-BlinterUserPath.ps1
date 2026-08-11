#Requires -Version 5.1
try {
    $binPath = '__BLINTER_BIN__'
    $path = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $path) { $path = '' }
    if ($path -notlike "*$binPath*") {
        if (-not $path) { $newPath = $binPath } else { $newPath = $path.TrimEnd(';') + ';' + $binPath }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Host 'Blinter added to User PATH permanently'
    }
    else {
        Write-Host 'Blinter already in User PATH'
    }
    exit 0
}
catch {
    Write-Host "ERROR: $_"
    exit 1
}
