@echo off
for /f "usebackq" %%i in (`echo hello`) do echo %%i
exit /b 0
