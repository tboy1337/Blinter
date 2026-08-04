@echo off
FOR /F "tokens=1,2" %%a IN ('type data.txt') DO echo %%a
