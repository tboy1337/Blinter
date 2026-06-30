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

set BLINTER_DIR=%LOCALAPPDATA%\Programs\Blinter
set BLINTER_BIN=%BLINTER_DIR%\bin
set BLINTER_RELEASE_FILE=%BLINTER_DIR%\installed_release.txt

echo +=====================+
echo + Blinter Uninstaller +
echo +=====================+
echo.

REM Check if Blinter is installed
if not exist "%BLINTER_BIN%" (
    echo Blinter installation not found at: %BLINTER_BIN%
    echo.
    echo Nothing to uninstall.
    goto :end
)

if not exist "%BLINTER_BIN%\blinter.exe" (
    if not exist "%BLINTER_RELEASE_FILE%" (
        echo Blinter installation not found at: %BLINTER_BIN%
        echo.
        echo Nothing to uninstall.
        goto :end
    )
)

REM Display current version if available
if exist "%BLINTER_BIN%\blinter.exe" (
    echo Current installed version:
    "%BLINTER_BIN%\blinter.exe" --version 2>nul
    echo.
)

if exist "%BLINTER_RELEASE_FILE%" (
    set /p INSTALLED_RELEASE=<"%BLINTER_RELEASE_FILE%"
    echo Installed release: !INSTALLED_RELEASE!
    echo.
)

REM Confirm uninstallation
echo This will remove Blinter from your system.
echo Installation directory: %BLINTER_DIR%
echo.
set /p CONFIRM="Are you sure you want to uninstall Blinter? (Y/N): "
if /i not "!CONFIRM!"=="Y" (
    echo.
    echo Uninstallation cancelled.
    goto :end
)

REM Check for and terminate running Blinter processes
echo.
echo Checking for running Blinter processes...
echo.

set PROCESSES_KILLED=0
for %%e in (blinter Blinter) do (
    tasklist /FI "IMAGENAME eq %%e.exe" 2>nul | find /I "%%e.exe" >nul 2>&1
    if !errorlevel! equ 0 (
        echo Terminating %%e.exe...
        taskkill /F /IM "%%e.exe" >nul 2>&1
        if !errorlevel! equ 0 (
            echo Terminated %%e.exe
            set PROCESSES_KILLED=1
        ) else (
            echo WARNING: Failed to terminate %%e.exe
        )
    )
)

if !PROCESSES_KILLED! equ 0 (
    echo No running Blinter processes found.
    echo.
) else (
    echo.
    echo Waiting for processes to fully terminate...
    timeout /t 2 /nobreak >nul 2>&1
    echo.
)

REM Remove Blinter executables and release marker
echo Removing Blinter files...
echo.

set REMOVAL_FAILED=0
if exist "%BLINTER_BIN%\blinter.exe" (
    del /F /Q "%BLINTER_BIN%\blinter.exe" >nul 2>&1
    if !errorlevel! equ 0 (
        echo Removed blinter.exe
    ) else (
        echo ERROR: Failed to remove blinter.exe. Error code: !errorlevel!
        set REMOVAL_FAILED=1
    )
)

if exist "%BLINTER_RELEASE_FILE%" (
    del /F /Q "%BLINTER_RELEASE_FILE%" >nul 2>&1
    if !errorlevel! equ 0 (
        echo Removed installed_release.txt
    ) else (
        echo ERROR: Failed to remove installed_release.txt. Error code: !errorlevel!
        set REMOVAL_FAILED=1
    )
)

if !REMOVAL_FAILED! equ 1 (
    echo.
    echo WARNING: Some files could not be removed.
    echo This may be because they are still in use or protected.
    echo.
)

REM Remove Blinter from PATH
echo.
echo Removing Blinter from User PATH...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $path = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($null -eq $path) { Write-Host 'User PATH is empty'; exit 0 }; if ($path -like '*%BLINTER_BIN%*') { $pathArray = $path -split ';' | Where-Object { $_ -ne '' -and $_ -ne '%BLINTER_BIN%' }; $newPath = $pathArray -join ';'; [Environment]::SetEnvironmentVariable('Path', $newPath, 'User'); Write-Host 'Blinter removed from User PATH' } else { Write-Host 'Blinter not found in User PATH' }; exit 0 } catch { Write-Host \"ERROR: $_\"; exit 1 }" 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Failed to remove Blinter from User PATH.
    echo You may need to manually remove it from your environment variables.
    echo.
)

REM Remove Blinter installation directory
echo.
echo Removing Blinter installation directory...
echo.
if exist "%BLINTER_DIR%" (
    rmdir /S /Q "%BLINTER_DIR%" >nul 2>&1
    if %errorlevel% equ 0 (
        echo Installation directory removed: %BLINTER_DIR%
        echo.
    ) else (
        echo WARNING: Failed to remove installation directory. Error code: %errorlevel%
        echo.
        echo This may be because files are in use or protected.
        echo You can manually delete: %BLINTER_DIR%
        echo.
        set REMOVAL_FAILED=1
    )
)

REM Display final status
echo.
if !REMOVAL_FAILED! equ 1 (
    echo +========================================+
    echo + Uninstallation completed with warnings +
    echo +========================================+
    echo.
    echo Some files or directories could not be removed.
    echo Please review the warnings above and take manual action if needed.
) else (
    echo +============================================+
    echo + SUCCESS: Blinter uninstalled successfully! +
    echo +============================================+
)
echo.
echo Note: You may need to restart your terminal or IDE for PATH changes to take effect.
echo.
goto :end

:error_exit
echo.
echo +==========================================================+
echo + Uninstallation failed. Please review the errors above. +
echo +==========================================================+
echo.
timeout /t 5 /nobreak
endlocal
exit /b 1

:end
endlocal
exit /b 0
