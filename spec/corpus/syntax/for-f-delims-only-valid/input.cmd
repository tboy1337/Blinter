@echo off
for /f "delims=" %%S in ('powershell -NoProfile -Command "Write-Output 42" 2^>nul') do (
    set VALUE=%%S
)
echo %VALUE%
