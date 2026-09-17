@echo off
for /f %%a in ('dir /b ^| sort') do echo %%a
if 1==1 (
  echo text ^(parens^)
)
exit /b 0
