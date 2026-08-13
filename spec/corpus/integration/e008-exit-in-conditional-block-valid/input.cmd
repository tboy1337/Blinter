@echo off
for %%e in (x) do if exist "%%~e" (
 exit /b
) >>log.txt 2>&1
if exist "folder" echo ok
