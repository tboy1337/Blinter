@echo off
for /f "skip=1 tokens=1-3" %%a in (data.txt) do echo %%a
