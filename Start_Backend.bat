@echo off
color 0A
echo =========================================
echo    STARTING SENTINEL AI BACKEND API
echo =========================================
echo.
cd backend
call venv\Scripts\activate.bat
echo Virtual environment activated.
echo Starting FastAPI Server...
python run_server.py
pause
