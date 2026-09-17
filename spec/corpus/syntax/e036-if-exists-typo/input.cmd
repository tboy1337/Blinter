@echo off
IF EXISTS file.txt echo found
IF NOT EXISTS other.txt echo missing
IF EXIT file.txt echo found
IF EXITS file.txt echo found
