# www.theforage.com - Telstra Cyber Task 3
# Firewall Server Handler

from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

host = "localhost"
port = 8000

# Malicious patterns to block
malicious_headers = {
    "suffix": "%>//",
    "c1": "Runtime",
    "c2": "<%",
    "Content-Type": "application/x-www-form-urlencoded"
}
malicious_data_pattern = "class.module.classLoader.resources.context.parent.pipeline.first.pattern"

# Handle the response here
def block_request(self):
    self.send_response(403)  # Forbidden
    self.send_header("content-type", "application/json")
    self.end_headers()
    response = {"message": "Request blocked due to malicious content"}
    self.wfile.write(bytes(str(response), "utf-8"))
    print("[!] Malicious request blocked.")

def handle_request(self):
    self.send_response(200)
    self.send_header("content-type", "application/json")
    self.end_headers()
    response = {"message": "Request allowed"}
    self.wfile.write(bytes(str(response), "utf-8"))
    print("[+] Request allowed.")

def inspect_request(self):
    # Check headers for malicious patterns
    for header_key, header_value in malicious_headers.items():
        if self.headers.get(header_key) == header_value:
            print("[!] Malicious header detected:", header_key)
            return True

    # Check the body (POST data) for malicious patterns
    content_length = int(self.headers.get('Content-Length', 0))
    if content_length > 0:
        post_data = self.rfile.read(content_length).decode('utf-8')
        parsed_data = urllib.parse.parse_qs(post_data)
        for key, value in parsed_data.items():
            if malicious_data_pattern in key:
                print("[!] Malicious data pattern detected:", key)
                return True

    return False

class ServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if inspect_request(self):
            block_request(self)
        else:
            handle_request(self)

    def do_POST(self):
        if inspect_request(self):
            block_request(self)
        else:
            handle_request(self)

if __name__ == "__main__":
    server = HTTPServer((host, port), ServerHandler)
    print("[+] Firewall Server")
    print("[+] HTTP Web Server running on: %s:%s" % (host, port))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    server.server_close()
    print("[+] Server terminated. Exiting...")
    exit(0)
