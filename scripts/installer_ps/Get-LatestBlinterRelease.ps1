#Requires -Version 5.1
$releases = Invoke-RestMethod -Uri 'https://api.github.com/repos/tboy1337/Blinter/releases?per_page=100'
$release = $releases | Where-Object { -not $_.prerelease -and -not $_.draft } | Select-Object -First 1
if (-not $release) { Write-Output 'NOT_FOUND'; exit 0 }
$asset = $release.assets | Where-Object { $_.name -like 'Blinter-v1.0.*.zip' } | Select-Object -First 1
if (-not $asset) { Write-Output 'NOT_FOUND'; exit 0 }
$line = $asset.browser_download_url + ' ' + $release.tag_name
Write-Output $line
