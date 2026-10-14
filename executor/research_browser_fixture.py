"""Synthetic owned UI fixture, NOT an injected Juice Shop vulnerability."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

COUNTS = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        COUNTS[self.path] = COUNTS.get(self.path, 0) + 1
        headers = {}
        status = 200
        if self.path.startswith("/ui"):
            safe = self.path.startswith("/ui-safe")
            sink = "textContent" if safe else "innerHTML"
            body = ('<!doctype html><title>Owned browser fixture</title><h1>Owned UI</h1>'
                '<input id="probe" aria-label="Probe"><button id="apply">Apply</button>'
                '<div id="result"></div><script src="/assets/ui.js"></script>'
                f'<script>window.fixtureSink="{sink}"</script>').encode()
            content_type = "text/html"
        elif self.path == "/assets/ui.js":
            body = b'''document.querySelector('#apply').addEventListener('click', () => {
                document.querySelector('#result')[window.fixtureSink] = document.querySelector('#probe').value;
                fetch('/private');
                fetch('http://outside.invalid/forbidden');
                new WebSocket('ws://outside.invalid/socket');
            });'''
            content_type = "application/javascript"
        elif self.path == "/redirect-local":
            status, headers, body, content_type = 302, {"Location":"/ui"}, b"", "text/plain"
        elif self.path == "/redirect-external":
            status, headers, body, content_type = 302, {"Location":"http://outside.invalid/forbidden"}, b"", "text/plain"
        elif self.path == "/counts":
            body, content_type = json.dumps(COUNTS).encode(), "application/json"
        else:
            status, body, content_type = 404, b"Not available", "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
