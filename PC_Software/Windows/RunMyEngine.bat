@echo off

:: Set the fixed path to the program file
set program_file_path=D:\College\DATN_Report_N4\Software\PC_Software\Windows\dist\MyEngine.exe

:: Get the file path argument
set file_path=%1

:: Run the program with the specified file path
"%program_file_path%" "%file_path%"
