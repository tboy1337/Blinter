@echo off
for /f "eol=; tokens=1" %%a in (data.txt) do echo %%a
