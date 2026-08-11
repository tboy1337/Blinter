@echo off
if exist file.txt (
    if !errorlevel! equ 0 (
        for /f "usebackq tokens=*" %%v in ("!VERSION_TEMP!") do set CURRENT_VERSION=%%v
    )
)
