# -*- coding: utf-8 -*-
# Burp Jython extension (legacy Extender API) - context menu sender for LLM Attack Lab bridge
#
# Features:
#   - Right-click request/response -> Send to LLM Attack Lab (/ingest)
#   - Right-click request/response -> Send to LLM Attack Lab (/ingest_stream)  [includes response body if present]
#   - Sends selected request bytes, optional response bytes, and content-type to local bridge
#
# Setup:
#   1) Start the bridge in LLM Attack Lab GUI (Burp tab) or CLI.
#   2) In Burp -> Extender -> Options, add Jython standalone JAR.
#   3) Add this .py as an extension.
#
# NOTE:
#   Burp's WebSocket APIs vary by version and are not consistently available in Jython.
#   For WebSocket transcripts, use ws_ingest_helper.py (copy frames from Burp WebSockets history/export).

from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.util import ArrayList
from java.awt.event import ActionListener
import json
import urllib2

BRIDGE_URL = "http://127.0.0.1:8765"   # change if needed
VERIFY_TLS = False


class _SendAction(ActionListener):
    def __init__(self, extender, invocation, endpoint):
        self.extender = extender
        self.invocation = invocation
        self.endpoint = endpoint

    def actionPerformed(self, event):
        try:
            messages = self.invocation.getSelectedMessages()
            if not messages or len(messages) == 0:
                self.extender._stdout.println("[LLM Lab] No selected messages.")
                return

            # Use first selected item (easy one-click flow)
            msg = messages[0]
            req_bytes = msg.getRequest()
            resp_bytes = msg.getResponse()
            service = msg.getHttpService()

            req_text = self.extender._helpers.bytesToString(req_bytes) if req_bytes else ""
            resp_text = self.extender._helpers.bytesToString(resp_bytes) if resp_bytes else ""

            content_type = ""
            if resp_bytes:
                try:
                    analyzed = self.extender._helpers.analyzeResponse(resp_bytes)
                    headers = analyzed.getHeaders()
                    for h in headers:
                        if str(h).lower().startswith("content-type:"):
                            content_type = str(h).split(":", 1)[1].strip()
                            break
                except:
                    pass

            scheme = "https"
            try:
                if service and service.getProtocol():
                    scheme = str(service.getProtocol())
            except:
                pass

            payload = {
                "raw_request": req_text,
                "scheme": scheme,
                "note": "Sent from Burp context menu",
            }
            if self.endpoint.endswith("/ingest_stream") and resp_text:
                payload["raw_response"] = resp_text
                payload["response_content_type"] = content_type

            body = json.dumps(payload)
            url = self.endpoint
            request = urllib2.Request(url, body, {"Content-Type": "application/json"})
            response = urllib2.urlopen(request, timeout=5)
            self.extender._stdout.println("[LLM Lab] Sent to %s -> HTTP %s" % (url, response.getcode()))
            self.extender._stdout.println(response.read())
        except Exception as e:
            self.extender._stdout.println("[LLM Lab] Error: %s" % str(e))


class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = callbacks.getStdout()
        callbacks.setExtensionName("LLM Attack Lab Bridge Sender")
        callbacks.registerContextMenuFactory(self)
        self._stdout.println("[LLM Lab] Context menu extension loaded. Bridge=%s" % BRIDGE_URL)

    def createMenuItems(self, invocation):
        items = ArrayList()

        items.add(JMenuItem(
            "Send to LLM Attack Lab (/ingest)",
            _SendAction(self, invocation, BRIDGE_URL + "/ingest")
        ))
        items.add(JMenuItem(
            "Send to LLM Attack Lab (/ingest_stream)",
            _SendAction(self, invocation, BRIDGE_URL + "/ingest_stream")
        ))
        return items
