"""Application entrypoint for NETPHISH Platform.

Author: Hrudyansh Kayastha
"""

import sys
import uvicorn
from app.config import APP_NAME, APP_VERSION, AUTHOR


def main():
    print("=" * 65)
    print(f" {APP_NAME} v{APP_VERSION} — Network Threat & Phishing Analysis Platform")
    print(f" Security Lead / Author: {AUTHOR}")
    print(" Architecture: Deterministic Heuristics & Forensic Correlation")
    print("=" * 65)
    print(" Starting local SOC console at http://127.0.0.1:8000")
    print(" REST API documentation available at http://127.0.0.1:8000/docs")
    print("=" * 65)

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
