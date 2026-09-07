@echo off
if %choice%==7 set X=C:Set-Permissions
call C:\Windows\ForEach-Object.bat
if %choice%==8 set X=C:\Windows\set-permissions.bat
exit /b 0
