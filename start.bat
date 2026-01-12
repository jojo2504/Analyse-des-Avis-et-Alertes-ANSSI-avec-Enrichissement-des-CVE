@echo off
REM Script to start both Django backend and React frontend on Windows

echo ================================
echo 🚀 Starting CVE Alert System
echo ================================

REM Start Django backend in a new window
echo.
echo 📦 Starting Django backend on http://127.0.0.1:8000
start "Django Backend" cmd /k "python manage.py runserver"

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
