# Burp integration (LLM Attack Lab)

## 1) HTTP / Streaming (SSE) one-click sender
Load `burp_extender_stub.py` in Burp Extender (Jython). It adds two context-menu actions:

- **Send to LLM Attack Lab (/ingest)** → sends the selected raw request
- **Send to LLM Attack Lab (/ingest_stream)** → sends the selected raw request **and** response body/content-type  
  (use this for streaming/SSE endpoints so the bridge can parse `text/event-stream` chunks)

The extension posts JSON to the local bridge (default `http://127.0.0.1:8765`).

## 2) WebSocket transcript capture
Burp WebSocket APIs differ across versions and Jython support is inconsistent.  
For reliable workflow:

1. Copy/export WebSocket frames/transcript from Burp (WebSockets history)
2. Save as a text file (one frame per line or pasted transcript)
3. Run:

```bash
python integrations/burp/ws_ingest_helper.py --file ws_frames.txt --target-url wss://target.example/ws
```

This posts to `POST /ingest_ws`, and the capture becomes visible in the GUI Burp tab.

## 3) Replay Diff Viewer
In the GUI Burp tab:
- Left editor = baseline raw request
- Right editor = attacked raw request
- Click **Replay Diff** to compare baseline vs attacked response bodies (unified diff)

## 4) Bridge endpoints
- `POST /ingest` - raw HTTP request capture
- `POST /ingest_stream` - raw HTTP request + optional response body (SSE parsing)
- `POST /ingest_ws` - WebSocket transcript/frames
- `GET /health` - health check
