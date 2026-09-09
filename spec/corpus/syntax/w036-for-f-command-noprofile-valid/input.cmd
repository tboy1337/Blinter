@echo off
for /f "usebackq delims=" %%V in (`powershell -NoProfile -Command "1+1"`) do set "D=%%V"
exit /b 0
