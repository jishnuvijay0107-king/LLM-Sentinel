@echo off
cd /d "%~dp0"
title Sentinel - AI message security
if not exist ".venv\Scripts\python.exe" (
    echo Create the environment first: python -m venv .venv
    echo Then install dependencies: .venv\Scripts\python.exe -m pip install -r requirements.txt
    pause
    exit /b 1
)
echo Sentinel is starting at http://127.0.0.1:8501
echo Press Ctrl+C to stop the app.
.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8501
