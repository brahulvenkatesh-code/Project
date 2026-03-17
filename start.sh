#!/bin/bash
# Start FastAPI backend in the background
echo "Starting FastAPI backend on port 8001..."
uvicorn api:app --host 0.0.0.0 --port 8001 &

# Start Streamlit UI in the foreground
echo "Starting Streamlit UI on port $PORT..."
streamlit run app.py --server.port $PORT --server.address 0.0.0.0
