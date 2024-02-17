@echo off
set file_path=%1

:: Get the current working directory (pwd)
for /f "delims=" %%a in ('cd') do set "current_dir=%%a"

:: Construct the full path to the program file
set program_file_path=%current_dir%\dist\MyEngine.exe

:: Run the program with the specified file path
"%program_file_path%" "%file_path%"