@echo off
DIR >log.txt 2>&1
echo x 2>>&1
exit /b 0
