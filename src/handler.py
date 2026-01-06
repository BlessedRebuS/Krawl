#!/usr/bin/env python3

import logging
import random
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler
from typing import Optional, List
from urllib.parse import urlparse, parse_qs

from config import Config
from tracker import AccessTracker
from analyzer import Analyzer
from templates import html_templates
from templates.dashboard_template import generate_dashboard
from generators import (
    credentials_txt, passwords_txt, users_json, api_keys_json,
    api_response, directory_listing, random_server_header
)
from wordlists import get_wordlists
from sql_errors import generate_sql_error_response, get_sql_response_with_data
from xss_detector import detect_xss_pattern, generate_xss_response
from server_errors import generate_server_error


class Handler(BaseHTTPRequestHandler):
    """HTTP request handler for the deception server"""
    webpages: Optional[List[str]] = None
    config: Config = None
    tracker: AccessTracker = None
    analyzer: Analyzer = None
    counter: int = 0
    app_logger: logging.Logger = None
    access_logger: logging.Logger = None
    credential_logger: logging.Logger = None

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

    def version_string(self) -> str:
        """Return custom server version for deception."""
        return random_server_header()

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
    
    def _parse_query_string(self) -> str:
        """Extract query string from the request path"""
        parsed = urlparse(self.path)
        return parsed.query
    
    def _handle_sql_endpoint(self, path: str) -> bool:
        """
        Handle SQL injection honeypot endpoints.
        Returns True if the path was handled, False otherwise.
        """
        # SQL-vulnerable endpoints
        sql_endpoints = ['/api/search', '/api/sql', '/api/database']
        
        base_path = urlparse(path).path
        if base_path not in sql_endpoints:
            return False
        
        try:
            # Get query parameters
            query_string = self._parse_query_string()
            
            # Log SQL injection attempt
            client_ip = self._get_client_ip()
            user_agent = self._get_user_agent()
            
            # Always check for SQL injection patterns
            error_msg, content_type, status_code = generate_sql_error_response(query_string or "")
            
            if error_msg:
                # SQL injection detected - log and return error
                self.access_logger.warning(f"[SQL INJECTION DETECTED] {client_ip} - {base_path} - Query: {query_string[:100] if query_string else 'empty'}")
                self.send_response(status_code)
                self.send_header('Content-type', content_type)
                self.end_headers()
                self.wfile.write(error_msg.encode())
            else:
                # No injection detected - return fake data
                self.access_logger.info(f"[SQL ENDPOINT] {client_ip} - {base_path} - Query: {query_string[:100] if query_string else 'empty'}")
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                response_data = get_sql_response_with_data(base_path, query_string or "")
                self.wfile.write(response_data.encode())
            
            return True
            
        except BrokenPipeError:
            # Client disconnected
            return True
        except Exception as e:
            self.app_logger.error(f"Error handling SQL endpoint {path}: {str(e)}")
            # Still send a response even on error
            try:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"error": "Internal server error"}')
            except:
                pass
            return True

    def generate_page(self, seed: str) -> str:
        """Generate a webpage containing random links or canary token"""
        random.seed(seed)
        num_pages = random.randint(*self.config.links_per_page_range)

        # Build the content HTML
        content = ""
        
        # Add canary token if needed
        if Handler.counter <= 0 and self.config.canary_token_url:
            content += f"""
            <div class="link-box canary-token">
                <a href="{self.config.canary_token_url}">{self.config.canary_token_url}</a>
            </div>
"""

        # Add links
        if self.webpages is None:
            for _ in range(num_pages):
                address = ''.join([
                    random.choice(self.config.char_space)
                    for _ in range(random.randint(*self.config.links_length_range))
                ])
                content += f"""
            <div class="link-box">
                <a href="{address}">{address}</a>
            </div>
"""
        else:
            for _ in range(num_pages):
                address = random.choice(self.webpages)
                content += f"""
            <div class="link-box">
                <a href="{address}">{address}</a>
            </div>
"""

        # Return the complete page using the template
        return html_templates.main_page(Handler.counter, content)

    def do_HEAD(self):
        """Sends header information"""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_POST(self):
        """Handle POST requests (mainly login attempts)"""
        client_ip = self._get_client_ip()
        user_agent = self._get_user_agent()
        post_data = ""

        from urllib.parse import urlparse
        base_path = urlparse(self.path).path
        
        if base_path in ['/api/search', '/api/sql', '/api/database']:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                post_data = self.rfile.read(content_length).decode('utf-8', errors="replace")
            
            self.access_logger.info(f"[SQL ENDPOINT POST] {client_ip} - {base_path} - Data: {post_data[:100] if post_data else 'empty'}")
            
            error_msg, content_type, status_code = generate_sql_error_response(post_data)
            
            try:
                if error_msg:
                    self.access_logger.warning(f"[SQL INJECTION DETECTED POST] {client_ip} - {base_path}")
                    self.send_response(status_code)
                    self.send_header('Content-type', content_type)
                    self.end_headers()
                    self.wfile.write(error_msg.encode())
                else:
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    response_data = get_sql_response_with_data(base_path, post_data)
                    self.wfile.write(response_data.encode())
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error in SQL POST handler: {str(e)}")
            return
        
        if base_path == '/api/contact':
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                post_data = self.rfile.read(content_length).decode('utf-8', errors="replace")
            
            parsed_data = {}
            for pair in post_data.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    from urllib.parse import unquote_plus
                    parsed_data[unquote_plus(key)] = unquote_plus(value)
            
            xss_detected = any(detect_xss_pattern(v) for v in parsed_data.values())
            
            if xss_detected:
                self.access_logger.warning(f"[XSS ATTEMPT DETECTED] {client_ip} - {base_path} - Data: {post_data[:200]}")
            else:
                self.access_logger.info(f"[XSS ENDPOINT POST] {client_ip} - {base_path}")
            
            try:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                response_html = generate_xss_response(parsed_data)
                self.wfile.write(response_html.encode())
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error in XSS POST handler: {str(e)}")
            return

        self.access_logger.warning(f"[LOGIN ATTEMPT] {client_ip} - {self.path} - {user_agent[:50]}")

        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            post_data = self.rfile.read(content_length).decode('utf-8', errors="replace")

            self.access_logger.warning(f"[POST DATA] {post_data[:200]}")

            # Parse and log credentials
            username, password = self.tracker.parse_credentials(post_data)
            if username or password:
                # Log to dedicated credentials.log file
                timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
                credential_line = f"{timestamp}|{client_ip}|{username or 'N/A'}|{password or 'N/A'}|{self.path}"
                self.credential_logger.info(credential_line)
                
                # Also record in tracker for dashboard
                self.tracker.record_credential_attempt(client_ip, self.path, username or 'N/A', password or 'N/A')
                
                self.access_logger.warning(f"[CREDENTIALS CAPTURED] {client_ip} - Username: {username or 'N/A'} - Path: {self.path}")

        # send the post data (body) to the record_access function so the post data can be used to detect suspicious things.
        self.tracker.record_access(client_ip, self.path, user_agent, post_data, method='POST')
        
        time.sleep(1)
        
        try:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(html_templates.login_error().encode())
        except BrokenPipeError:
            # Client disconnected before receiving response, ignore silently
            pass
        except Exception as e:
            # Log other exceptions but don't crash
            self.app_logger.error(f"Failed to send response to {client_ip}: {str(e)}")

    def serve_special_path(self, path: str) -> bool:
        """Serve special paths like robots.txt, API endpoints, etc."""
        
        # Check SQL injection honeypot endpoints first
        if self._handle_sql_endpoint(path):
            return True
        
        try:
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
            
            if path in ['/admin', '/admin/', '/admin/login', '/login']:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html_templates.login_form().encode())
                return True
            
            if path in ['/users', '/user', '/database', '/db', '/search']:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html_templates.product_search().encode())
                return True
            
            if path in ['/info', '/input', '/contact', '/feedback', '/comment']:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html_templates.input_form().encode())
                return True
            
            if path == '/server':
                error_html, content_type = generate_server_error()
                self.send_response(500)
                self.send_header('Content-type', content_type)
                self.end_headers()
                self.wfile.write(error_html.encode())
                return True
            
            if path in ['/wp-login.php', '/wp-login', '/wp-admin', '/wp-admin/']:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(html_templates.wp_login().encode())
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
        except BrokenPipeError:
            # Client disconnected, ignore silently
            pass
        except Exception as e:
            self.app_logger.error(f"Failed to serve special path {path}: {str(e)}")
            pass

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
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error generating dashboard: {e}")
            return
        
        # API endpoint for fetching IP stats
        if self.config.dashboard_secret_path and self.path.startswith(f"{self.config.dashboard_secret_path}/api/ip-stats/"):
            ip_address = self.path.replace(f"{self.config.dashboard_secret_path}/api/ip-stats/", "")
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            # Prevent browser caching - force fresh data from database every time
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            self.end_headers()
            try:
                from database import get_database
                import json
                db = get_database()
                ip_stats = db.get_ip_stats_by_ip(ip_address)
                if ip_stats:
                    self.wfile.write(json.dumps(ip_stats).encode())
                else:
                    self.wfile.write(json.dumps({'error': 'IP not found'}).encode())
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error fetching IP stats: {e}")
                self.wfile.write(json.dumps({'error': str(e)}).encode())
            return

        self.tracker.record_access(client_ip, self.path, user_agent, method='GET')
        
        self.analyzer.infer_user_category(client_ip)

        if self.tracker.is_suspicious_user_agent(user_agent):
            self.access_logger.warning(f"[SUSPICIOUS] {client_ip} - {user_agent[:50]} - {self.path}")

        if self._should_return_error():
            error_code = self._get_random_error_code()
            self.access_logger.info(f"Returning error {error_code} to {client_ip} - {self.path}")
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
        except BrokenPipeError:
            # Client disconnected, ignore silently
            pass
        except Exception as e:
            self.app_logger.error(f"Error generating page: {e}")

    def log_message(self, format, *args):
        """Override to customize logging - uses access logger"""
        client_ip = self._get_client_ip()
        self.access_logger.info(f"{client_ip} - {format % args}")
