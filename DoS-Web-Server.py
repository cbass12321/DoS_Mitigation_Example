import subprocess
import logging
import time
import socketserver
from collections import defaultdict
import re
import os

# Set IP and port for webserver.
HOST_ADDRESS = "192.168.56.2"
PORT = 80

# Teting for detecting basic directory traverserables
Directory_Traversal_Patterns = re.compile(r"/\.\.\/|\/etc\/passwd|\/proc\/|\/dev\/")

# Thresholds for DoS detection
request_threshhold = 100  # Number of requests
TIME_WINDOW = 60  # Time window in seconds

# Dictionary to store request counts for each IP address
request_counts = defaultdict(int)

# Variable to store the time of the last reset
last_timer_reset = time.time()

# Set to store blocked IP addresses
blocked_ips = set()

class RequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        global request_counts, last_timer_reset
        
        # Check if it's time to reset the request counts
        current_time = time.time()
        if current_time - last_timer_reset >= TIME_WINDOW:
            # Reset request counts
            request_counts.clear()
            # Update the last reset time
            last_timer_reset = current_time

        # Snag clients IP address
        client_ip = self.client_address[0]

        # If IP is blocked is in blocked IPs, immeditiently drop and response with 403 forbidden message
        if client_ip in blocked_ips:
            logging.warning("Blocked request from %s", client_ip)
            self.request.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return

        # Store the amount of requests a client makes
        request_counts[client_ip] += 1
        
        # Receive the request client_data
        client_data = self.request.recv(1024).strip()
        
        # Log request
        request_info = client_data.decode("utf-8").split()[:2]
        logging.info("Request from %s: %s %s", client_ip, *request_info)
        
        # Check for Directory Traverseal
        if Directory_Traversal_Patterns.search(client_data.decode("utf-8")):
            logging.warning("Abnormal request detected from: %s", client_ip)
            self.request.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        else:
            # Serve files by sending an HTTP response
            file_path = client_data.decode("utf-8").split()[1].lstrip("/")
            if os.path.exists(file_path) and os.path.isfile(file_path):
                with open(file_path, "rb") as file:
                    file_content = file.read()
                response = b"HTTP/1.1 200 OK\r\n\r\n" + file_content
                self.request.sendall(response)
            else:
                self.request.sendall(b"HTTP/1.1 404 Not Found\r\n\r\nFile not found")
            
        # Check for DoS attack, aka DoS monitoring and detection
        if request_counts[client_ip] >= request_threshhold:
            # 
            logging.warning("Potential DoS attack detected from: %s", client_ip)
            self.block_ip_address(client_ip)

    # Function used to actuall block/mitigates the IPs
    def block_ip_address(self, client_ip):
        # Add the client IP address to the blocked ips list
        blocked_ips.add(client_ip)
        # Close the connection to the blocked 
        self.request.close()
        # Output the IP being blocked
        logging.warning("Blocking IP address: %s", client_ip)

# Classify server type
class HTTPServer(socketserver.TCPServer):
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.shutdown()
# Start server
def start_server():
    logging.info("Starting HTTP server...")
    with HTTPServer((HOST_ADDRESS, PORT), RequestHandler) as server:
        server.serve_forever()

def main():
    # Configure logging for trouble shooting
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    # Start the HTTP server
    start_server()

if __name__ == "__main__":
    main()
