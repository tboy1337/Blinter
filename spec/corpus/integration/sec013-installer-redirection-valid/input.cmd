@echo off
setlocal
set "BIN=%LOCALAPPDATA%\Programs\Blinter\bin"
set "OUT=%LOCALAPPDATA%\Programs\Blinter\version.txt"
"%BIN%\blinter.exe" --version > "%OUT%" 2>&1
curl -L -o "%LOCALAPPDATA%\Programs\Blinter\download.zip" "https://example.com/file.zip" 2>&1
endlocal
exit /b 0
