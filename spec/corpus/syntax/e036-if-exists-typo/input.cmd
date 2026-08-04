@echo off
IF EXISTS file.txt echo found
IF NOT EXISTS other.txt echo missing
