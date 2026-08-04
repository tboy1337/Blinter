@echo off
for /f "tokens=1-2" %%a in ("one two") do (
echo %%c
)
