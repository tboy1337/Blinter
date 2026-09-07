@echo off
FOR /F "usebackq tokens=1" %%a IN ('datafile.txt') DO echo %%a
exit /b 0
