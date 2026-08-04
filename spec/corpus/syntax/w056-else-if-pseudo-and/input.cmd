@echo off
set a=1
set b=2
if %a%==1 (echo ok) else if %a% equ 1 and %b% equ 2 (echo bad)
