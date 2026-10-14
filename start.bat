@echo off
title LLM-Sentinel Launcher
color 0b
echo ============================================================
echo   [SENTINEL] AI Security Gateway & Threat Interceptor
echo ============================================================
echo.

if not exist ".venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found at .venv\
    echo Please create it first: python -m venv .venv
    pause
    exit /b 1
)

echo [*] Activating virtual environment...
call .venv\Scripts\activate.bat

echo [*] Launching FastAPI Gateway on http://127.0.0.1:8001...
start "Sentinel Gateway API" /B .venv\Scripts\uvicorn backend.app.main:app --host 127.0.0.1 --port 8001

echo [*] Waiting for gateway to initialize...
timeout /t 2 /nobreak >nul

echo [*] Launching Cinematic SOC Dashboard on http://localhost:8501...
start http://localhost:8501
.venv\Scripts\streamlit run dashboard/app.py --server.port 8501 --server.headless true

pause
