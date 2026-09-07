@echo off
if "%~1"=="" goto :from_if
if "%~1"=="x" goto :from_bare
echo x || goto :from_or
if "%~1"=="" call :from_if_call
call :from_bare_call
exit /b 0
:from_if
exit /b 0
:from_bare
exit /b 0
:from_or
exit /b 0
:from_if_call
exit /b 0
:from_bare_call
exit /b 0
