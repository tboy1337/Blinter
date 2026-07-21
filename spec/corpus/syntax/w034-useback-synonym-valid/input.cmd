@echo off
FOR /F "useback tokens=*" %%i IN (`echo hello`) DO echo %%i
