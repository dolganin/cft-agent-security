"""Synthetic R06 HTTP control fixture, Docker-only tests; not Juice Shop or a benchmark."""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        owner = self.headers.get("Authorization") == "Bearer " + os.environ["OWNER_TOKEN"]
        if self.path == "/health":
            status, body = 200, {"ready": True}
        elif self.path == "/owner" and owner or self.path == "/probe" and os.environ["FIXTURE_MODE"] == "disclosed":
            status, body = 200, {"marker": os.environ["OWNED_MARKER"]}
        else:
            status, body = 403, {"denied": True}
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
