@echo off
echo ok >nul && echo and-ok
nonexistentcmd 2>nul || echo or-ok
