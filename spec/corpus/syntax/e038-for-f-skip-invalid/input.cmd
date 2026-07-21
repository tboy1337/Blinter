@echo off
for /f "skip=abc tokens=1" %%a in (data.txt) do echo %%a
