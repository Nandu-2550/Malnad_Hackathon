@echo off
title REVIVER - Digital Forensics & Data Carving Suite
echo =====================================================================
echo       REVIVER // CYBER FORENSICS & RECONSTRUCTION SUITE
echo =====================================================================
echo.

cd /d "%~dp0"

REM Step 1: Ensure .env exists from template
if not exist ".env" (
    if exist ".env.example" (
        echo [Setup] Initializing environment config from template...
        copy ".env.example" ".env" >nul
    ) else if exist "..\.env.example" (
        echo [Setup] Initializing environment config from template...
        copy "..\.env.example" ".env" >nul
    )
)

REM Step 2: Auto-verify / install Python dependencies
echo [Check] Verifying Python libraries...
python -c "import customtkinter, PIL, requests" 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [Setup] Installing missing dependencies from requirements.txt...
    pip install -r requirements.txt
)

REM Step 3: Launch Application
echo [Launch] Starting REVIVER Desktop Application...
python app.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Trying python from user AppData...
    "%LOCALAPPDATA%\Python\bin\python.exe" app.py
)
pause
