@echo off
goto :afterjs

@if (1==1) @end /*
cscript //nologo //E:JScript "%~f0" %*
exit /b
*/
WScript.Echo("Hello from JScript!")
var x = 1

:afterjs
echo done
exit /b 0
