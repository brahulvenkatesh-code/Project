#!/bin/bash
# Railway startup script for dual-service (FastAPI + Streamlit)

# 1. Start FastAPI backend (Port 8001)
echo "Starting backend service..."
uvicorn api:app --host 0.0.0.0 --port 8001 &

# 2. Start Streamlit frontend (Bound to Railway's $PORT)
echo "Starting frontend service on port $PORT..."
streamlit run app.py --server.port $PORT --server.address 0.0.0.0
