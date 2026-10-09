import http.server
import socket
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))
PORT = 8000
Handler = http.server.SimpleHTTPRequestHandler

class DualStackServer(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
    def server_bind(self):
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except Exception:
            pass
        super().server_bind()

if __name__ == '__main__':
    try:
        httpd = DualStackServer(('::', PORT), Handler)
    except Exception:
        httpd = http.server.ThreadingHTTPServer(('127.0.0.1', PORT), Handler)
    
    print(f"Smart Campus Server running at http://localhost:{PORT} and http://127.0.0.1:{PORT}")
    httpd.serve_forever()
