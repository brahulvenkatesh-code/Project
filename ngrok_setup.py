"""
ngrok_setup.py — Automatic ngrok tunnel manager
Starts a public HTTPS tunnel to the FastAPI endpoint (port 8001).
Prints the public URL for submission.

Usage:
    python ngrok_setup.py              # starts tunnel, prints URL
    python ngrok_setup.py --test       # starts + tests the endpoint
"""

import os, sys, time, json, requests
from dotenv import load_dotenv

load_dotenv()

API_PORT    = int(os.environ.get("API_PORT", 8001))
NGROK_TOKEN = os.environ.get("NGROK_AUTHTOKEN", "")
BEARER      = os.environ.get("API_BEARER_TOKEN", "giggso-ps2-secret-token")


def start_tunnel(port: int = API_PORT) -> str:
    """Start ngrok tunnel and return public HTTPS URL."""
    from pyngrok import ngrok, conf

    # Set auth token if provided
    if NGROK_TOKEN:
        conf.get_default().auth_token = NGROK_TOKEN
    
    # Kill any existing tunnels first
    ngrok.kill()
    time.sleep(1)

    # Open new tunnel
    tunnel = ngrok.connect(port, "http")
    public_url = tunnel.public_url.replace("http://", "https://")

    return public_url


def print_banner(public_url: str):
    print()
    print("=" * 60)
    print("  NANOBOT — PUBLIC ENDPOINT ACTIVE")
    print("=" * 60)
    print(f"  Public URL  : {public_url}")
    print(f"  Endpoint    : {public_url}/analyze")
    print(f"  Health      : {public_url}/health")
    print(f"  Auth header : Authorization: Bearer {BEARER}")
    print()
    print("  SUBMIT THIS TO HR:")
    print(f"  POST {public_url}/analyze")
    print(f"  Authorization: Bearer {BEARER}")
    print("=" * 60)
    print()


def test_endpoint(public_url: str) -> bool:
    """Test the public endpoint with a sample payload."""
    print("Testing public endpoint...")

    # Health check
    try:
        r = requests.get(f"{public_url}/health", timeout=10)
        if r.status_code == 200:
            print(f"  ✅ Health check: {r.json()}")
        else:
            print(f"  ❌ Health check failed: {r.status_code}")
            return False
    except Exception as e:
        print(f"  ❌ Cannot reach endpoint: {e}")
        return False

    # Analyze test
    sample = {
        "metrics_json": json.dumps({
            "performance_metrics": {
                "accuracy": 0.92,
                "f1_score": 0.87,
                "precision": 0.89,
                "recall":    0.85,
                "auc_roc":   0.95
            },
            "drift_metrics": {
                "psi_score": 0.08,
                "feature_drift_score": 0.05
            }
        })
    }
    try:
        r = requests.post(
            f"{public_url}/analyze",
            json=sample,
            headers={"Authorization": f"Bearer {BEARER}"},
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            print(f"  ✅ /analyze: risk_level={data.get('risk_level')} ✅")
            print(f"  ✅ Endpoint verified and working")
            return True
        else:
            print(f"  ❌ /analyze failed: {r.status_code} — {r.text[:100]}")
            return False
    except Exception as e:
        print(f"  ❌ /analyze error: {e}")
        return False


def save_url_to_env(public_url: str):
    """Append PUBLIC_URL to .env for reference."""
    env_path = ".env"
    content = open(env_path).read() if os.path.exists(env_path) else ""
    
    # Remove old PUBLIC_URL line if present
    lines = [l for l in content.splitlines() if not l.startswith("PUBLIC_URL=")]
    lines.append(f"PUBLIC_URL={public_url}")
    
    with open(env_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  ✅ Public URL saved to .env")


if __name__ == "__main__":
    test_mode = "--test" in sys.argv

    print("Starting ngrok tunnel...")

    try:
        url = start_tunnel()
        print_banner(url)
        save_url_to_env(url)

        if test_mode:
            print()
            success = test_endpoint(url)
            if not success:
                print("\n  ⚠️  Make sure 'uvicorn api:app --port 8001' is running first.")
        else:
            print("  ℹ️  Run with --test flag to verify the endpoint:")
            print("  python ngrok_setup.py --test")
            print()
            print("  Tunnel is active. Press Ctrl+C to stop.")
            print()
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n  Tunnel stopped.")

    except Exception as e:
        print(f"\n❌ ngrok error: {e}")
        print("\nTo fix:")
        print("  1. Install ngrok: https://ngrok.com/download")
        print("  2. Get free auth token: https://dashboard.ngrok.com")
        print("  3. Add to .env: NGROK_AUTHTOKEN=your_token_here")
        print("  4. Or run manually: ngrok http 8001")
        sys.exit(1)
