#!/usr/bin/env python3
"""PoC round-robin HTTP ingress. No affinity or authorization state."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import itertools
import sys
import threading

host, port = sys.argv[1].rsplit(':', 1)
backends = itertools.cycle(sys.argv[2:])
lock = threading.Lock()
hop = {'connection', 'transfer-encoding', 'keep-alive', 'proxy-authenticate',
       'proxy-authorization', 'te', 'trailer', 'upgrade', 'content-length'}

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.forward()

    def do_POST(self):
        self.forward()

    def do_OPTIONS(self):
        self.forward()

    def forward(self):
        with lock:
            backend = next(backends)
        connection = http.client.HTTPConnection(backend, timeout=15)
        try:
            length = int(self.headers.get('content-length', '0'))
            if length < 0 or length > 2 * 1024 * 1024:
                self.send_error(413)
                return
            body = self.rfile.read(length) if length else None
            connection.request(self.command, self.path, body,
                               {k: v for k, v in self.headers.items() if k.lower() not in hop})
            response = connection.getresponse()
            data = response.read()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in hop:
                    self.send_header(key, value)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (OSError, http.client.HTTPException):
            self.send_error(502)
        finally:
            connection.close()

    def log_message(self, *_):
        pass

ThreadingHTTPServer((host, int(port)), Handler).serve_forever()
