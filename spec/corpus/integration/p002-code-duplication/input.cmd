@echo off
robocopy %SOURCE% %DEST% /MIR /COPYALL /R:3 /W:10 /LOG:backup.log extra
robocopy %SOURCE% %DEST% /MIR /COPYALL /R:3 /W:10 /LOG:backup2.log extra
robocopy %SOURCE% %DEST% /MIR /COPYALL /R:3 /W:10 /LOG:backup3.log extra
robocopy %SOURCE% %DEST% /MIR /COPYALL /R:3 /W:10 /LOG:backup4.log extra
