@echo off
goto :aftercsharp

:csharpblock
using System;
namespace Demo
public class Helper

:aftercsharp
set HEX=0x1A
echo %HEX%
exit /b 0
