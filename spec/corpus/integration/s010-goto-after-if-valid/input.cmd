@echo off
if "%~1"=="" goto :from_if
dir || goto :from_or
goto :from_bare

:from_if
exit /b 0

:from_or
exit /b 0

:from_bare
exit /b 0
