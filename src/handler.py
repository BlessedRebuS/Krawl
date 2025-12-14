#!/usr/bin/env python3

import random
import time
from http.server import BaseHTTPRequestHandler
from typing import Optional, List
from datetime import datetime

from config import Config
from tracker import AccessTracker
from templates import html_templates
from templates.dashboard_template import generate_dashboard
from generators import (
    credentials_txt, passwords_txt, users_json, api_keys_json,
    api_response, directory_listing
)
from wordlists import get_wordlists


class Handler(BaseHTTPRequestHandler):
    """HTTP request handler for the deception server"""
    webpages: Optional[List[str]] = None
    config: Config = None
    tracker: AccessTracker = None
    counter: int = 0

    def _get_client_ip(self) -> str:
        """Extract client IP address from request, checking proxy headers first"""
        # Headers might not be available during early error logging
        if hasattr(self, 'headers') and self.headers:
            # Check X-Forwarded-For header (set by load balancers/proxies)
            forwarded_for = self.headers.get('X-Forwarded-For')
            if forwarded_for:
                # X-Forwarded-For can contain multiple IPs, get the first (original client)
                return forwarded_for.split(',')[0].strip()
            
            # Check X-Real-IP header (set by nginx and other proxies)
            real_ip = self.headers.get('X-Real-IP')
            if real_ip:
                return real_ip.strip()
        
        # Fallback to direct connection IP
        return self.client_address[0]

    def _get_user_agent(self) -> str:
        """Extract user agent from request"""
        return self.headers.get('User-Agent', '')

    def _should_return_error(self) -> bool:
        """Check if we should return an error based on probability"""
        if self.config.probability_error_codes <= 0:
            return False
        return random.randint(1, 100) <= self.config.probability_error_codes

    def _get_random_error_code(self) -> int:
        """Get a random error code from wordlists"""
        wl = get_wordlists()
        error_codes = wl.error_codes
        if not error_codes:
            error_codes = [400, 401, 403, 404, 500, 502, 503]
        return random.choice(error_codes)

    def generate_page(self, seed: str) -> str:
        """Generate a webpage containing random links or canary token"""
        random.seed(seed)
        num_pages = random.randint(*self.config.links_per_page_range)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Krawl</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #0d1117;
            color: #c9d1d9;
            margin: 0;
            padding: 40px 20px;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
        }}
        .container {{
            max-width: 1200px;
            width: 100%;
        }}
        h1 {{
            color: #f85149;
            text-align: center;
            font-size: 48px;
            margin: 60px 0 30px;
        }}
        .counter {{
            color: #f85149;
            text-align: center;
            font-size: 56px;
            font-weight: bold;
            margin-bottom: 60px;
        }}
        .links-container {{
            display: flex;
            flex-direction: column;
            gap: 20px;
            align-items: center;
        }}
        .link-box {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 15px 30px;
            min-width: 300px;
            text-align: center;
            transition: all 0.3s ease;
        }}
        .link-box:hover {{
            background: #1c2128;
            border-color: #58a6ff;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(88, 166, 255, 0.2);
        }}
        a {{
            color: #58a6ff;
            text-decoration: none;
            font-size: 20px;
            font-weight: 700;
        }}
        a:hover {{
            color: #79c0ff;
        }}
        .canary-token {{
            background: #1c1917;
            border: 2px solid #f85149;
            border-radius: 8px;
            padding: 30px 50px;
            margin: 40px auto;
            max-width: 800px;
            overflow-x: auto;
        }}
        .canary-token a {{
            color: #f85149;
            font-size: 18px;
            white-space: nowrap;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Krawl me! &#128376;</h1>
        <div class="counter">{Handler.counter}</div>
        
        <div class="links-container">
"""

        if Handler.counter <= 0 and self.config.canary_token_url:
            html += f"""
            <div class="link-box canary-token">
                <a href="{self.config.canary_token_url}">{self.config.canary_token_url}</a>
            </div>
"""

        if self.webpages is None:
            for _ in range(num_pages):
                address = ''.join([
                    random.choice(self.config.char_space)
                    for _ in range(random.randint(*self.config.links_length_range))
                ])
                html += f"""
            <div class="link-box">
                <a href="{address}">{address}</a>
            </div>
"""
        else:
            for _ in range(num_pages):
                address = random.choice(self.webpages)
                html += f"""
            <div class="link-box">
                <a href="{address}">{address}</a>
            </div>
"""

        html += """
        </div>
    </div>
</body>
</html>"""
        return html

    def do_HEAD(self):
        """Sends header information"""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_POST(self):
        """Handle POST requests (mainly login attempts)"""
        client_ip = self._get_client_ip()
        user_agent = self._get_user_agent()
        
        self.tracker.record_access(client_ip, self.path, user_agent)
        
        print(f"[LOGIN ATTEMPT] {client_ip} - {self.path} - {user_agent[:50]}")
        
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            post_data = self.rfile.read(content_length).decode('utf-8')
            print(f"[POST DATA] {post_data[:200]}")
        
        time.sleep(1)
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html_templates.login_error().encode())

    def serve_special_path(self, path: str) -> bool:
        """Serve special paths like robots.txt, API endpoints, etc."""
        
        if path == '/robots.txt':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(html_templates.robots_txt().encode())
            return True
        
        if path in ['/credentials.txt', '/passwords.txt', '/admin_notes.txt']:
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            if 'credentials' in path:
                self.wfile.write(credentials_txt().encode())
            else:
                self.wfile.write(passwords_txt().encode())
            return True
        
        if path in ['/users.json', '/api_keys.json', '/config.json']:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            if 'users' in path:
                self.wfile.write(users_json().encode())
            elif 'api_keys' in path:
                self.wfile.write(api_keys_json().encode())
            else:
                self.wfile.write(api_response('/api/config').encode())
            return True
        
        if path in ['/admin', '/admin/', '/admin/login', '/login', '/wp-login.php']:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html_templates.login_form().encode())
            return True
        
        if path == '/wp-admin' or path == '/wp-admin/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html_templates.login_form().encode())
            return True
        
        if path in ['/wp-content/', '/wp-includes/'] or 'wordpress' in path.lower():
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html_templates.wordpress().encode())
            return True
        
        if 'phpmyadmin' in path.lower() or path in ['/pma/', '/phpMyAdmin/']:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html_templates.phpmyadmin().encode())
            return True
        
        if path.startswith('/api/') or path.startswith('/api') or path in ['/.env']:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(api_response(path).encode())
            return True
        
        if path in ['/backup/', '/uploads/', '/private/', '/admin/', '/config/', '/database/']:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(directory_listing(path).encode())
            return True
        
        return False

    def do_GET(self):
        """Responds to webpage requests"""
        client_ip = self._get_client_ip()
        user_agent = self._get_user_agent()
        
        if self.config.dashboard_secret_path and self.path == self.config.dashboard_secret_path:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            try:
                stats = self.tracker.get_stats()
                self.wfile.write(generate_dashboard(stats).encode())
            except Exception as e:
                print(f"Error generating dashboard: {e}")
            return

        self.tracker.record_access(client_ip, self.path, user_agent)

        if self.tracker.is_suspicious_user_agent(user_agent):
            print(f"[SUSPICIOUS] {client_ip} - {user_agent[:50]} - {self.path}")

        if self._should_return_error():
            error_code = self._get_random_error_code()
            print(f"[ERROR] Returning {error_code} to {client_ip} - {self.path}")
            self.send_response(error_code)
            self.end_headers()
            return

        if self.serve_special_path(self.path):
            return

        time.sleep(self.config.delay / 1000.0)
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        try:
            self.wfile.write(self.generate_page(self.path).encode())
            
            Handler.counter -= 1
            
            if Handler.counter < 0:
                Handler.counter = self.config.canary_token_tries
        except Exception as e:
            print(f"Error generating page: {e}")

    def log_message(self, format, *args):
        """Override to customize logging"""
        client_ip = self._get_client_ip()
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {client_ip} - {format % args}")
