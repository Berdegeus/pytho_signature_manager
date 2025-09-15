import http.server
import socketserver
import urllib.request
import urllib.parse
import os

BACKEND_HOST = os.environ.get('BACKEND_HOST', 'app')
BACKEND_PORT = int(os.environ.get('BACKEND_PORT', '8080'))
ROUTER_PORT = int(os.environ.get('ROUTER_PORT', '80'))

class Proxy(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.proxy()

    def do_GET(self):
        self.proxy()

    def do_POST(self):
        self.proxy(with_body=True)

    def do_PUT(self):
        self.proxy(with_body=True)

    def do_PATCH(self):
        self.proxy(with_body=True)

    def do_DELETE(self):
        self.proxy()

    def log_message(self, format, *args):
        # quieter logs
        return

    def proxy(self, with_body=False):
        try:
            # Build target URL
            qs = ('?' + urllib.parse.urlencode(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))) if urllib.parse.urlsplit(self.path).query else ''
            path = urllib.parse.urlsplit(self.path).path
            target = f"http://{BACKEND_HOST}:{BACKEND_PORT}{path}{qs}"

            # Prepare request
            method = self.command
            headers = {k: v for k, v in self.headers.items() if k.lower() not in {'host', 'content-length', 'accept-encoding'}}
            data = None
            if with_body:
                length = int(self.headers.get('Content-Length', '0'))
                data = self.rfile.read(length) if length > 0 else None

            req = urllib.request.Request(target, data=data, method=method, headers=headers)

            # Forward request
            with urllib.request.urlopen(req, timeout=30) as resp:
                self.send_response(resp.getcode())
                # Copy response headers (some hop-by-hop headers excluded)
                for k, v in resp.getheaders():
                    if k.lower() not in {'transfer-encoding', 'content-encoding', 'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'upgrade'}:
                        self.send_header(k, v)
                self.end_headers()
                body = resp.read()
                self.wfile.write(body)
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            for k, v in e.headers.items():
                if k.lower() not in {'transfer-encoding', 'content-encoding', 'connection'}:
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            self.send_response(502)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(str(e).encode('utf-8'))

if __name__ == '__main__':
    with socketserver.TCPServer(("0.0.0.0", ROUTER_PORT), Proxy) as httpd:
        print(f"Router listening on :{ROUTER_PORT}, proxying to {BACKEND_HOST}:{BACKEND_PORT}")
        httpd.serve_forever()
