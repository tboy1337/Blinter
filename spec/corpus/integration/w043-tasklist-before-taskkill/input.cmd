@echo off
setlocal enabledelayedexpansion
for %%e in (notepad) do (
    tasklist /FI "IMAGENAME eq %%e.exe" 2>nul | find /I "%%e.exe" >nul 2>&1
    if !errorlevel! equ 0 (
        taskkill /F /FI "IMAGENAME eq %%e.exe" /IM "%%e.exe" >nul 2>&1
    )
)
