#!/usr/bin/env python3
"""Send WebSocket transcripts/frames to the LLM Attack Lab local bridge (/ingest_ws).

Usage examples:
  python ws_ingest_helper.py --file ws_frames.txt
  python ws_ingest_helper.py --file burp_ws_export.txt --bridge http://127.0.0.1:8765 --target-url wss://api.example/ws
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import httpx


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True, help="Text file with WS frames (one per line or pasted transcript)")
    ap.add_argument("--bridge", default="http://127.0.0.1:8765", help="Bridge base URL")
    ap.add_argument("--target-url", default="", help="Optional WebSocket URL")
    ap.add_argument("--note", default="WS transcript from Burp/export", help="Optional note")
    args = ap.parse_args()

    txt = Path(args.file).read_text(encoding="utf-8", errors="ignore")
    frames = [ln for ln in txt.splitlines() if ln.strip()]
    payload = {
        "target_url": args.target_url,
        "note": args.note,
        "frames": frames,
    }
    with httpx.Client(timeout=10) as client:
        r = client.post(args.bridge.rstrip("/") + "/ingest_ws", json=payload)
        print(r.status_code)
        print(r.text)


if __name__ == "__main__":
    main()
