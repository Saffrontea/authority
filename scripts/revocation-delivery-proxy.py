#!/usr/bin/env python3
"""E2E-only loopback proxy: interrupt automatic delivery without changing services."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
from urllib.parse import urlsplit


def main():
    upstream = urlsplit(sys.argv[1])
    if upstream.scheme != 'http' or not upstream.hostname or upstream.path:
        raise SystemExit('expected an HTTP agent origin')
    lock = threading.Lock()
    state = {'blocked': False, 'rejected': 0, 'forwarded': 0, 'rejected_sequences': []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass  # Signed envelopes and browser proofs must not enter test logs.

        def reply(self, status, body, headers=()):
            self.send_response(status)
            for name, value in headers:
                if name.lower() not in {'content-length', 'connection', 'transfer-encoding'}:
                    self.send_header(name, value)
            self.send_header('content-length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def dispatch(self):
            body = self.rfile.read(int(self.headers.get('content-length', '0')))
            # Holding this lock through forwarding makes a successful block ACK
            # a barrier: all earlier automatic deliveries have finished.
            with lock:
                if self.command == 'POST' and self.path == '/__e2e/delivery':
                    value = json.loads(body)
                    if type(value.get('blocked')) is not bool:
                        self.reply(400, b'{}')
                        return
                    state['blocked'] = value['blocked']
                    self.reply(200, json.dumps(state).encode(), [('content-type', 'application/json')])
                    return
                if self.command == 'POST' and self.path == '/v1/revocations' and state['blocked']:
                    state['rejected'] += 1
                    sequence = json.loads(body)['notice']['sequence']
                    if sequence not in state['rejected_sequences']:
                        state['rejected_sequences'].append(sequence)
                    self.reply(503, b'{"error":"e2e_delivery_interrupted"}', [('content-type', 'application/json')])
                    return
                connection = http.client.HTTPConnection(upstream.hostname, upstream.port, timeout=10)
                try:
                    headers = {name: value for name, value in self.headers.items()
                               if name.lower() not in {'host', 'connection', 'content-length'}}
                    connection.request(self.command, self.path, body, headers)
                    response = connection.getresponse()
                    data = response.read()
                    if self.command == 'POST' and self.path == '/v1/revocations' and 200 <= response.status < 300:
                        state['forwarded'] += 1
                    self.reply(response.status, data, response.getheaders())
                except OSError:
                    self.reply(502, b'{"error":"upstream_unavailable"}', [('content-type', 'application/json')])
                finally:
                    connection.close()

        do_GET = do_POST = do_OPTIONS = dispatch

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    Path(sys.argv[2]).write_text(f'http://127.0.0.1:{server.server_port}')
    server.serve_forever()


if __name__ == '__main__':
    main()
