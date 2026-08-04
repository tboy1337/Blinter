@echo off
:retry_loop
net start MyService
IF ERRORLEVEL 1 GOTO retry_loop
