@echo off
for /f "eol=XY tokens=1" %%a in (data.txt) do echo %%a
