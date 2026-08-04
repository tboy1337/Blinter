@echo off
FOR /F "delims=," %%i IN (data.csv) DO echo %%i
