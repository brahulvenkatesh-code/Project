#!/bin/bash
# Start the FastAPI backend in the background
uvicorn api:app --host 0.0.0.0 --port 8001 &

# Start the Streamlit UI in the foreground
python -m streamlit run app.py --server.port ${PORT:-8501} --server.address 0.0.0.0
