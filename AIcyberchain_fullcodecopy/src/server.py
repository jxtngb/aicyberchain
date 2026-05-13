from http.server import BaseHTTPRequestHandler, HTTPServer

class MyServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Hello, this is a test server")

server = HTTPServer(("127.0.0.1", 8080), MyServer)
print("Server running on http://127.0.0.1:8080")
server.serve_forever()
