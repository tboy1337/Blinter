@echo off
setlocal enabledelayedexpansion

REM Attempt to change to system drive to avoid issues with current directory/drive
cd /d "%SystemDrive%" >nul 2>&1
if %errorlevel% neq 0 (
    echo Failed to change to %SystemDrive%. Error code: %errorlevel%
)

REM Check if running as administrator (script should run as normal user)
net session >nul 2>&1
if %errorlevel% equ 0 (
    echo ERROR: This script is intended to be run as a user. Please run without administrator privileges.
    goto :error_exit
)

REM Check if curl is installed
where curl >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Curl is not installed or in PATH.
    goto :error_exit
)

echo +===========================+
echo + Blinter Installer/Updater +
echo +===========================+
echo.

REM Detect latest Blinter version and download URL from GitHub API
set BLINTER_URL=
set BLINTER_VERSION=

for /f "delims=" %%i in ('powershell -NoProfile -Command "$releases = Invoke-RestMethod -Uri 'https://api.github.com/repos/tboy1337/Blinter/releases?per_page=100'; $release = $releases | Where-Object { -not $_.prerelease -and -not $_.draft } | Select-Object -First 1; if ($release) { $asset = $release.assets | Where-Object { $_.name -like 'Blinter-v1.0.*.zip' } | Select-Object -First 1; if ($asset) { Write-Output ($asset.browser_download_url + '|' + $release.tag_name) } else { Write-Output 'NOT_FOUND' } } else { Write-Output 'NOT_FOUND' }" 2^>nul') do (
    for /f "tokens=1,2 delims=|" %%a in ("%%i") do (
        set BLINTER_URL=%%a
        set BLINTER_VERSION=%%b
    )
)

if "!BLINTER_URL!"=="NOT_FOUND" (
    echo ERROR: Failed to find Windows download URL from GitHub API.
    echo.
    echo Please check your internet connection and try again.
    goto :error_exit
)

if "!BLINTER_URL!"=="" (
    echo ERROR: Failed to detect latest Blinter version.
    echo.
    echo Please check your internet connection and try again.
    goto :error_exit
)

if "!BLINTER_VERSION!"=="" (
    echo ERROR: Failed to parse Blinter version from GitHub API response.
    echo.
    echo Cannot proceed with installation.
    goto :error_exit
)

echo Latest Blinter release: !BLINTER_VERSION!
echo.

set BLINTER_DIR=%LOCALAPPDATA%\Programs\Blinter
set BLINTER_BIN=%BLINTER_DIR%\bin
set BLINTER_RELEASE_FILE=%BLINTER_DIR%\installed_release.txt
set BLINTER_TEMP=%TEMP%\blinter_install_%RANDOM%_%RANDOM%
set BLINTER_BACKUP=%TEMP%\blinter_backup_%RANDOM%_%RANDOM%

REM Create installation directory if it doesn't exist
if not exist "%BLINTER_BIN%" (
    mkdir "%BLINTER_BIN%" >nul 2>&1
    if !errorlevel! neq 0 (
        echo ERROR: Failed to create installation directory: %BLINTER_BIN%
        echo Error code: !errorlevel!
        goto :error_exit
    )
)

REM Check current installation
set CURRENT_VERSION=
set NEEDS_BACKUP=0

if exist "%BLINTER_BIN%\blinter.exe" (
    set "VERSION_TEMP=%TEMP%\blinter_version_%RANDOM%_%RANDOM%.txt"
    "%BLINTER_BIN%\blinter.exe" --version > "!VERSION_TEMP!" 2>&1
    if !errorlevel! equ 0 (
        for /f "usebackq delims=" %%v in ("!VERSION_TEMP!") do set CURRENT_VERSION=%%v
        del /F /Q "!VERSION_TEMP!" >nul 2>&1
        if not "!CURRENT_VERSION!"=="" (
            echo Current installed version: !CURRENT_VERSION!
            echo.
        )
    ) else (
        if exist "!VERSION_TEMP!" del /F /Q "!VERSION_TEMP!" >nul 2>&1
    )
)

if exist "%BLINTER_RELEASE_FILE%" (
    set /p INSTALLED_RELEASE=<"%BLINTER_RELEASE_FILE%"
    if "!INSTALLED_RELEASE!"=="!BLINTER_VERSION!" (
        echo Blinter !BLINTER_VERSION! is already installed and up to date.
        goto :end
    )
    if exist "%BLINTER_BIN%\blinter.exe" (
        echo Upgrading from !INSTALLED_RELEASE! to !BLINTER_VERSION!...
        echo.
        set NEEDS_BACKUP=1
    )
) else if exist "%BLINTER_BIN%\blinter.exe" (
    echo Existing installation found without release marker.
    echo.
    echo Upgrading to !BLINTER_VERSION!...
    echo.
    set NEEDS_BACKUP=1
) else (
    echo No existing installation found.
    echo.
    echo Installing Blinter !BLINTER_VERSION!...
    echo.
)

REM Backup existing installation if upgrading
if !NEEDS_BACKUP! equ 1 (
    echo Creating backup of existing installation...
    echo.
    mkdir "%BLINTER_BACKUP%" >nul 2>&1
    if exist "%BLINTER_BIN%\blinter.exe" copy /Y "%BLINTER_BIN%\blinter.exe" "%BLINTER_BACKUP%\" >nul 2>&1
    if exist "%BLINTER_RELEASE_FILE%" copy /Y "%BLINTER_RELEASE_FILE%" "%BLINTER_BACKUP%\" >nul 2>&1

    if exist "%BLINTER_BIN%\blinter.exe" del /F /Q "%BLINTER_BIN%\blinter.exe" >nul 2>&1
)

REM Download Blinter
echo Downloading Blinter !BLINTER_VERSION! from:
echo !BLINTER_URL!
echo.
curl -L -f --progress-bar -o "%BLINTER_TEMP%.zip" "!BLINTER_URL!" 2>&1
if !errorlevel! neq 0 (
    echo.
    echo ERROR: Failed to download Blinter. Error code: !errorlevel!
    echo.
    echo This could be due to:
    echo - Network connectivity issues
    echo - Invalid download URL
    goto :error_restore
)

REM Validate downloaded file exists and has content
if not exist "%BLINTER_TEMP%.zip" (
    echo ERROR: Downloaded file not found at %BLINTER_TEMP%.zip
    goto :error_restore
)
for %%A in ("%BLINTER_TEMP%.zip") do set FILESIZE=%%~zA
if !FILESIZE! lss 500000 (
    echo ERROR: Downloaded file is too small ^(!FILESIZE! bytes^). Download may be corrupted.
    goto :error_restore
)

REM Extract Blinter
echo.
echo Extracting Blinter...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Expand-Archive -Path '%BLINTER_TEMP%.zip' -DestinationPath '%BLINTER_TEMP%' -Force -ErrorAction Stop; exit 0 } catch { Write-Host \"ERROR: $_\"; exit 1 }" 2>&1
if !errorlevel! neq 0 (
    echo ERROR: Failed to extract Blinter archive. Error code: !errorlevel!
    goto :error_restore
)

REM Locate extracted executable
set BLINTER_SOURCE_EXE=
for /f "delims=" %%f in ('dir /b "%BLINTER_TEMP%\Blinter-v1.0.*.exe" 2^>nul') do set BLINTER_SOURCE_EXE=!BLINTER_TEMP!\%%f

if "!BLINTER_SOURCE_EXE!"=="" (
    echo ERROR: Blinter executable not found in extracted archive.
    echo.
    echo The archive structure may have changed or be corrupted.
    goto :error_restore
)

REM Install Blinter executable
echo Installing Blinter executable...
echo.
copy /Y "!BLINTER_SOURCE_EXE!" "%BLINTER_BIN%\blinter.exe" >nul 2>&1
if !errorlevel! neq 0 (
    echo ERROR: Failed to install blinter.exe. Error code: !errorlevel!
    echo.
    echo Installation failed. Check if files are in use or if you have write permissions.
    goto :error_restore
)
echo Installed blinter.exe

REM Verify installation
echo.
echo Verifying installation...
echo.
if not exist "%BLINTER_BIN%\blinter.exe" (
    echo ERROR: blinter.exe not found after installation at %BLINTER_BIN%\blinter.exe
    goto :error_restore
)

"%BLINTER_BIN%\blinter.exe" --version 2>&1
if !errorlevel! neq 0 (
    echo ERROR: blinter.exe failed to execute. Error code: !errorlevel!
    goto :error_restore
)

REM Write release marker
echo !BLINTER_VERSION!> "%BLINTER_RELEASE_FILE%"
if !errorlevel! neq 0 (
    echo WARNING: Failed to write release marker at %BLINTER_RELEASE_FILE%
    echo.
)

REM Update PATH environment variable
echo.
echo Updating PATH environment variable...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $path = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($null -eq $path) { $path = '' }; if ($path -notlike '*%BLINTER_BIN%*') { $newPath = if ($path -eq '') { '%BLINTER_BIN%' } else { $path.TrimEnd(';') + ';%BLINTER_BIN%' }; [Environment]::SetEnvironmentVariable('Path', $newPath, 'User'); Write-Host 'Blinter added to User PATH permanently' } else { Write-Host 'Blinter already in User PATH' }; exit 0 } catch { Write-Host \"ERROR: $_\"; exit 1 }" 2>&1
if !errorlevel! neq 0 (
    echo WARNING: Failed to update User PATH environment variable.
    echo You may need to manually add %BLINTER_BIN% to your PATH.
    echo.
)

REM Update PATH for current session
set "PATH=%PATH%;%BLINTER_BIN%"

REM Success! Clean up temporary files and backup
call :cleanup
if exist "%BLINTER_BACKUP%" rmdir /S /Q "%BLINTER_BACKUP%" >nul 2>&1

echo.
echo +============================================================+
echo + SUCCESS: Blinter !BLINTER_VERSION! installed successfully! +
echo +============================================================+
echo.
echo Installation directory: %BLINTER_BIN%
echo.
echo Note: You may need to restart your terminal or IDE to use Blinter commands.
echo In the current session, Blinter commands should already be available.
echo.
goto :end

:error_restore
REM Attempt to restore backup if upgrade failed
if !NEEDS_BACKUP! equ 1 (
    if exist "%BLINTER_BACKUP%" (
        echo.
        echo Attempting to restore previous installation...
        if exist "%BLINTER_BACKUP%\blinter.exe" copy /Y "%BLINTER_BACKUP%\blinter.exe" "%BLINTER_BIN%\" >nul 2>&1
        if exist "%BLINTER_BACKUP%\installed_release.txt" copy /Y "%BLINTER_BACKUP%\installed_release.txt" "%BLINTER_DIR%\" >nul 2>&1
        echo Previous installation restored.
        echo.
    )
)

:error_cleanup
REM Clean up temporary files and backup
call :cleanup
if exist "%BLINTER_BACKUP%" rmdir /S /Q "%BLINTER_BACKUP%" >nul 2>&1

:error_exit
echo.
echo +========================================================+
echo + Installation failed. Please review the errors above. +
echo +========================================================+
echo.
echo For help, visit: https://github.com/tboy1337/Blinter/issues
echo.
timeout /t 5 /nobreak
endlocal
exit /b 1

:end
timeout /t 5 /nobreak
endlocal
exit /b 0

:cleanup
REM Subroutine to clean up temporary files
if exist "%BLINTER_TEMP%.zip" del /F /Q "%BLINTER_TEMP%.zip" >nul 2>&1
if exist "%BLINTER_TEMP%" rmdir /S /Q "%BLINTER_TEMP%" >nul 2>&1
exit /b 0
