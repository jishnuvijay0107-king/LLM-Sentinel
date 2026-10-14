#!/usr/bin/env bash
# LLM-Sentinel Linux/macOS Startup Script

echo "============================================================"
echo "  [SENTINEL] AI Security Gateway & Threat Interceptor"
echo "============================================================"

if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
elif [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

echo "[*] Launching FastAPI Gateway on http://127.0.0.1:8001..."
uvicorn backend.app.main:app --host 127.0.0.1 --port 8001 &
GATEWAY_PID=$!

sleep 2

echo "[*] Launching Cinematic SOC Dashboard on http://localhost:8501..."
streamlit run dashboard/app.py --server.port 8501 --server.headless true &
DASHBOARD_PID=$!

trap "kill $GATEWAY_PID $DASHBOARD_PID" EXIT
wait
