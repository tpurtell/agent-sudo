#!/usr/bin/env python3
"""A deterministic stand-in for an OpenAI-compatible decision model.

It reads the request state and answers like a careful model would, so the
delegation tests do not depend on a real provider:
- package installs that mention nvidia/cuda/headers: low risk, relevant to driver work
- anything with `nginx`: low risk but unrelated to the driver intent
- root shells: high risk
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

def assess(state):
    req = state.get("request", {})
    words = " ".join([req.get("command") or ""] + req.get("arguments", [])).lower()
    delegation = state.get("delegation")
    driver = any(k in words for k in ("nvidia", "cuda", "headers", "dkms"))
    risk, decision, relevance = 22, "approve", 0.9 if driver else 0.1
    if "nginx" in words:
        relevance, decision = 0.05, "ask"
    if req.get("command", "").endswith(("bash", "sh")):
        risk, decision = 90, "ask"
    return {
        "risk": risk,
        "confidence": 0.85,
        "dimensions": {"destructive": 0.05, "privilege_escape": 0.05, "persistence": 0.6, "credential_access": 0.0,
                       "network_security": 0.0, "availability": 0.1, "unusual": 0.1},
        "relevance": relevance if delegation else None,
        "suggestion": {"decision": decision, "command": "exact", "hosts": "host", "requester": "session", "ttl_minutes": 30},
        "summary": f"Mock assessment of {words[:60]}",
        "reasons": ["deterministic mock"],
    }

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        state = json.loads(body["messages"][1]["content"])
        out = json.dumps({"model": "mock", "choices": [{"message": {"content": json.dumps(assess(state))}}], "usage": {"cost": 0}}).encode()
        self.send_response(200); self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out))); self.end_headers(); self.wfile.write(out)
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

ThreadingHTTPServer(("0.0.0.0", 8000), H).serve_forever()
