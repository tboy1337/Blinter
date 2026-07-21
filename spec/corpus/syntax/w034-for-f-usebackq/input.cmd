@echo off
FOR /F "tokens=1" %%a IN (`echo hello world`) DO echo %%a
