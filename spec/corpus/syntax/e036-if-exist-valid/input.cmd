@echo off
IF EXIST file.txt echo found
IF NOT EXIST other.txt echo missing
