"""
start.py — One-command launcher
Starts Streamlit + FastAPI + ngrok tunnel together.

Usage:
    python start.py

What it does:
    1. Starts FastAPI on port 8001 (background)
    2. Starts ngrok tunnel → prints public URL
    3. Starts Streamlit on port 8501 (foreground)
    4. Ctrl+C stops everything cleanly
"""

import os, sys, time, signal, subprocess, threading
from dotenv import load_dotenv

load_dotenv()

STREAMLIT_PORT = int(os.environ.get("STREAMLIT_PORT", 8501))
API_PORT       = int(os.environ.get("API_PORT", 8001))
BEARER         = os.environ.get("API_BEARER_TOKEN", "giggso-ps2-secret-token")

processes = []


def cleanup(sig=None, frame=None):
    print("\n\nShutting down all services...")
    for p in processes:
        try:
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            try: p.kill()
            except: pass
    try:
        from pyngrok import ngrok
        ngrok.kill()
    except Exception:
        pass
    print("✅ All services stopped.")
    sys.exit(0)


signal.signal(signal.SIGINT,  cleanup)
signal.signal(signal.SIGTERM, cleanup)


def start_api():
    """Start FastAPI in background."""
    print(f"[API] Starting FastAPI on port {API_PORT}...")
    p = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api:app",
         "--host", "0.0.0.0", "--port", str(API_PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    processes.append(p)
    time.sleep(2)  # Wait for API to be ready

    if p.poll() is not None:
        print(f"[API] ❌ Failed to start — check api.py")
        out, err = p.communicate()
        print(err.decode()[:300])
        return False

    print(f"[API] ✅ Running on http://localhost:{API_PORT}")
    return True


def start_ngrok():
    """Start ngrok tunnel and return public URL."""
    print(f"[ngrok] Starting tunnel to port {API_PORT}...")
    try:
        from pyngrok import ngrok, conf
        token = os.environ.get("NGROK_AUTHTOKEN", "")
        if token:
            conf.get_default().auth_token = token

        ngrok.kill()
        time.sleep(1)
        tunnel = ngrok.connect(API_PORT, "http")
        url = tunnel.public_url.replace("http://", "https://")

        print(f"[ngrok] ✅ Public URL: {url}")
        print()
        print("=" * 60)
        print("  SUBMIT THIS TO HR:")
        print(f"  POST {url}/analyze")
        print(f"  Authorization: Bearer {BEARER}")
        print("=" * 60)
        print()

        # Save to .env
        env = open(".env").read() if os.path.exists(".env") else ""
        lines = [l for l in env.splitlines() if not l.startswith("PUBLIC_URL=")]
        lines.append(f"PUBLIC_URL={url}")
        open(".env", "w").write("\n".join(lines) + "\n")

        return url
    except Exception as e:
        print(f"[ngrok] ⚠️  Could not start tunnel: {e}")
        print(f"[ngrok] Run manually: ngrok http {API_PORT}")
        return None


def start_streamlit():
    """Start Streamlit (foreground)."""
    print(f"[Streamlit] Starting on http://localhost:{STREAMLIT_PORT}...")
    p = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "app.py",
         "--server.port", str(STREAMLIT_PORT),
         "--server.headless", "true"],
    )
    processes.append(p)
    print(f"[Streamlit] ✅ Open http://localhost:{STREAMLIT_PORT}")
    print()
    print("Press Ctrl+C to stop all services.")
    p.wait()


if __name__ == "__main__":
    print()
    print("=" * 60)
    print("  NANOBOT — Model Performance Explainer")
    print("  Starting all services...")
    print("=" * 60)
    print()

    # 1. Start API
    api_ok = start_api()

    # 2. Start ngrok
    public_url = start_ngrok()

    # 3. Start Streamlit (blocks until Ctrl+C)
    start_streamlit()
