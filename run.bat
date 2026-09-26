@echo off
title REVIVER - Digital Forensics & Data Carving Suite
echo =====================================================================
echo       REVIVER // CYBER FORENSICS & RECONSTRUCTION SUITE
echo =====================================================================
echo.

cd /d "%~dp0"

REM Step 1: Ensure .env exists from template
if not exist "calmstacks-reconstructor\.env" (
    if exist "calmstacks-reconstructor\.env.example" (
        echo [Setup] Initializing environment config from template...
        copy "calmstacks-reconstructor\.env.example" "calmstacks-reconstructor\.env" >nul
    ) else if exist ".env.example" (
        echo [Setup] Initializing environment config from template...
        copy ".env.example" "calmstacks-reconstructor\.env" >nul
    )
)

REM Step 2: Auto-verify / install Python dependencies
echo [Check] Verifying Python libraries...
python -c "import customtkinter, PIL, requests" 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [Setup] Installing missing dependencies from requirements.txt...
    pip install -r requirements.txt
    if %ERRORLEVEL% NEQ 0 (
        echo [Warning] pip install had issues. Attempting to launch anyway...
    )
)

REM Step 3: Launch Application
echo [Launch] Starting REVIVER Desktop Application...
cd /d "%~dp0calmstacks-reconstructor"
python app.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Trying python from user AppData...
    "%LOCALAPPDATA%\Python\bin\python.exe" app.py
)
pause
