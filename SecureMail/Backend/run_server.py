"""
Entry point to launch the SecureMail Backend server.
"""
import uvicorn
import os
import sys

# Ensure backend root is on path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"Starting SecureMail API Server on http://localhost:{port}")
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=True)
