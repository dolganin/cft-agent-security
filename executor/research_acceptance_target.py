"""Fixed synthetic transport fixture for R02/R03; not a vulnerability benchmark."""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://outside.invalid/")
            self.end_headers()
            return
        if self.path == "/private":
            allowed = self.headers.get("Authorization") == "Bearer " + os.environ["FIXTURE_TOKEN"]
            self.send_response(200 if allowed else 401)
            value = {"identity": "fixture-owner" if allowed else None,
                     "reflected": self.headers.get("Authorization", "")}
        else:
            self.send_response(200)
            value = {"health": "ok", "path": self.path}
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(value).encode())

    def do_POST(self):
        body = self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 16384))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
