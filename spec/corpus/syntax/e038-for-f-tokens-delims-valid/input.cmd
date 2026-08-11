@echo off
for /f "tokens=1,2 delims=|" %%a in ("url|tag") do (
    echo %%a %%b
)
