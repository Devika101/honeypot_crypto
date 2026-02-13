#!/usr/bin/env python3
"""
Simple Honeypot Demo Server
This demonstrates how honeypots catch hackers by creating fake websites
"""

from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import os
from datetime import datetime
from urllib.parse import urlparse
import threading
import time

class Color:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

# Store all attack attempts
attack_log = []
attack_count = 0

class HoneypotHandler(SimpleHTTPRequestHandler):
    """Custom HTTP handler that logs all requests"""
    
    def do_GET(self):
        """Handle GET requests"""
        print(f"{Color.CYAN}[VISIT]{Color.END} Someone accessed: {self.path}")
        
        # Serve the appropriate HTML file
        if self.path == '/' or self.path == '/index.html':
            self.path = '/demo_presentation.html'
        elif self.path == '/bank':
            self.path = '/fake_bank.html'
        elif self.path == '/admin':
            self.path = '/fake_admin.html'
        elif self.path == '/wallet':
            self.path = '/fake_crypto_wallet.html'
        
        return SimpleHTTPRequestHandler.do_GET(self)
    
    def do_POST(self):
        """Handle POST requests (login attempts)"""
        global attack_count
        
        if self.path == '/log_attempt':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                attack_count += 1
                
                # Log the attack
                attack_info = {
                    'id': attack_count,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'type': data.get('type', 'unknown'),
                    'username': data.get('username', ''),
                    'ip': self.client_address[0],
                    'user_agent': self.headers.get('User-Agent', 'Unknown')
                }
                attack_log.append(attack_info)
                
                # Print colorful alert
                print(f"\n{Color.RED}{Color.BOLD}{'='*60}{Color.END}")
                print(f"{Color.RED}{Color.BOLD}🚨 HACKER CAUGHT! Attack #{attack_count}{Color.END}")
                print(f"{Color.RED}{Color.BOLD}{'='*60}{Color.END}")
                print(f"{Color.YELLOW}Type:{Color.END} {data.get('type', 'unknown').upper()}")
                print(f"{Color.YELLOW}Time:{Color.END} {attack_info['timestamp']}")
                print(f"{Color.YELLOW}Username:{Color.END} {data.get('username', 'N/A')}")
                print(f"{Color.YELLOW}IP Address:{Color.END} {attack_info['ip']}")
                if 'password' in data:
                    print(f"{Color.YELLOW}Password:{Color.END} {'*' * len(data['password'])} (captured)")
                print(f"{Color.RED}{Color.BOLD}{'='*60}{Color.END}\n")
                
                # Save to file
                with open('attack_log.json', 'w') as f:
                    json.dump(attack_log, f, indent=2)
                
                # Send response
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'logged'}).encode())
                
            except Exception as e:
                print(f"Error logging attack: {e}")
                self.send_response(500)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

def print_banner():
    """Print a cool startup banner"""
    banner = f"""
{Color.CYAN}{Color.BOLD}
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🍯  HONEYPOT SECURITY DEMONSTRATION  🍯                ║
║                                                           ║
║   How We Stop Hackers with Fake Websites                 ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
{Color.END}

{Color.GREEN}What is a Honeypot?{Color.END}
A honeypot is a FAKE website that looks real but is actually a trap
for hackers. When hackers try to attack it, we catch them!

{Color.YELLOW}How it works:{Color.END}
1. We create fake websites (bank, admin panel, crypto wallet)
2. Hackers think they're real and try to hack them
3. We log everything: their IP, what they tried, when they tried it
4. We use this info to protect REAL websites

{Color.MAGENTA}{'='*60}{Color.END}
{Color.BOLD}Server Status: RUNNING{Color.END}
{Color.BOLD}Port: 8080{Color.END}
{Color.MAGENTA}{'='*60}{Color.END}

{Color.GREEN}📱 Open in your browser:{Color.END}
  → Main Demo:    {Color.CYAN}http://localhost:8080/{Color.END}
  → Fake Bank:    {Color.CYAN}http://localhost:8080/bank{Color.END}
  → Fake Admin:   {Color.CYAN}http://localhost:8080/admin{Color.END}
  → Fake Wallet:  {Color.CYAN}http://localhost:8080/wallet{Color.END}

{Color.YELLOW}💡 Try to "hack" these sites and watch them get caught!{Color.END}
{Color.RED}Press Ctrl+C to stop the server{Color.END}

{Color.MAGENTA}{'='*60}{Color.END}
"""
    print(banner)

def stats_monitor():
    """Monitor and display statistics"""
    while True:
        time.sleep(30)  # Every 30 seconds
        if attack_count > 0:
            print(f"\n{Color.GREEN}📊 Statistics: {attack_count} attack(s) caught so far!{Color.END}")

def main():
    """Start the honeypot server"""
    # Change to demo directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    print_banner()
    
    # Start statistics monitor in background
    stats_thread = threading.Thread(target=stats_monitor, daemon=True)
    stats_thread.start()
    
    # Start server
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, HoneypotHandler)
    
    print(f"{Color.GREEN}✅ Honeypot server is ready!{Color.END}")
    print(f"{Color.YELLOW}Waiting for hackers to fall into our trap...{Color.END}\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n\n{Color.YELLOW}Shutting down server...{Color.END}")
        print(f"{Color.GREEN}Total attacks caught: {attack_count}{Color.END}")
        if attack_count > 0:
            print(f"{Color.GREEN}Attack log saved to: attack_log.json{Color.END}")
        print(f"{Color.CYAN}Thank you for using Honeypot Demo!{Color.END}\n")
        httpd.shutdown()

if __name__ == '__main__':
    main()
