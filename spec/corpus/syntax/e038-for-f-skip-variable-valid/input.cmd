@echo off
for /f "skip=%@KEEP_HISTORICAL% tokens=*" %%v in ('dir /b') do echo %%v
