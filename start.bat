@echo off
REM Script to start both Django backend and React frontend on Windows

echo ================================
echo Starting CVE Alert System
echo ================================

REM Check if virtual environment exists, if not create it
set VENV_DIR=
if exist "venv" (
    set VENV_DIR=venv
) else if exist ".venv" (
    set VENV_DIR=.venv
) else (
    echo.
    echo Creating virtual environment...
    python -m venv venv
    set VENV_DIR=venv
    echo Virtual environment created
)

REM Activate virtual environment
echo.
echo Activating virtual environment...
call %VENV_DIR%\Scripts\activate.bat

REM Install Python requirements
echo.
echo Installing Python dependencies...
pip install -q -r requirements.txt
echo Python dependencies installed

REM Install npm dependencies in cve-frontend
echo.
echo Installing npm dependencies in cve-frontend...
cd cve-frontend
call npm install
cd ..
echo npm dependencies installed

REM Start Django backend in a new window
echo.
echo Starting Django backend on http://127.0.0.1:8000
start "Django Backend" cmd /k "call ..\%VENV_DIR%\Scripts\activate.bat && python manage.py runserver"

REM Wait a moment for backend to start
timeout /t 2 /nobreak >nul

REM Start React frontend in a new window
echo.
echo ⚛️  Starting React frontend on http://localhost:3000
start "React Frontend" cmd /k "cd cve-frontend && npm start"

echo.
echo ================================
echo ✅ Both servers are starting!
echo ================================
echo Backend:  http://127.0.0.1:8000
echo Frontend: http://localhost:3000
echo.
echo Close the terminal windows to stop the servers
echo ================================
echo.

pause
