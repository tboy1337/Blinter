@echo off
setlocal enabledelayedexpansion
for %%A in (%TEMP%\example.zip) do set FILESIZE=%%~zA
echo !FILESIZE!
