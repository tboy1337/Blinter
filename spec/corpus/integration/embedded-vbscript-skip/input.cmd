@echo off
goto :aftervbs

:vbsblock
Dim obj
Set obj = CreateObject("Scripting.FileSystemObject")
Option Explicit
MsgBox "hi"

:aftervbs
echo done
exit /b 0
