@echo off
title REVIVER - Digital Forensics & Data Carving Suite
echo Starting REVIVER Desktop Application...
python app.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo An error occurred launching app.py with default python. Trying python from AppData...
    "%LOCALAPPDATA%\Python\bin\python.exe" app.py
)
pause
