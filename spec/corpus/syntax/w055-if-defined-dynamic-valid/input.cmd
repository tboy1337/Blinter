@echo off
call :check stk1
goto :eof
:check
if defined stk%~1 echo ok
goto :eof
