#!/usr/bin/env python3
"""A deterministic stand-in for an OpenAI-compatible decision model.

It reads the request state and answers like a careful model would, so the
delegation tests do not depend on a real provider:
- package installs that mention nvidia/cuda/headers/dkms: low risk, "installing driver packages"
- anything with `nginx`: low risk, "installing web server packages"
- root shells: high risk
Fit with each delegation is high when the delegation's intent names that kind of work.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KINDS = [
    (("nvidia", "cuda", "headers", "dkms"), "installing driver packages", ("driver", "nvidia")),
    (("nginx",), "installing web server packages", ("web server", "nginx")),
]

def assess(state):
    req = state.get("request", {})
    words = " ".join([req.get("command") or ""] + req.get("arguments", [])).lower()
    kind, markers = "running maintenance commands", ()
    for keys, k, m in KINDS:
        if any(x in words for x in keys):
            kind, markers = k, m
            break
    risk, decision = 22, "approve"
    if (req.get("command") or "").endswith(("bash", "sh")):
        risk, decision = 90, "ask"
    fit = []
    for d in state.get("delegations", []):
        intent = d.get("intent", "").lower()
        fit.append({"id": d["id"], "p": 0.9 if markers and any(m in intent for m in markers) else 0.05})
    return {
        "risk": risk,
        "confidence": 0.85,
        "dimensions": {"destructive": 0.05, "privilege_escape": 0.05, "persistence": 0.6, "credential_access": 0.0,
                       "network_security": 0.0, "availability": 0.1, "unusual": 0.1},
        "decision": decision,
        "fit": fit,
        "suggestion": {"remember": "program", "prefix_len": 0, "kind_of_work": kind, "hosts": "host",
                       "requester": "session", "duration": "1d"},
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
