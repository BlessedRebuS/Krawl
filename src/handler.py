#!/usr/bin/env python3

import logging
import random
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler
from typing import Optional, List
from urllib.parse import urlparse, parse_qs, unquote_plus
import json
import os

from database import get_database
from config import Config, get_config

# imports for the __init_subclass__ method, do not remove pls
from firewall.fwtype import FWType
from firewall.iptables import Iptables
from firewall.raw import Raw

from tracker import AccessTracker
from templates import html_templates
from templates.dashboard_template import generate_dashboard
from generators import (
    credentials_txt,
    passwords_txt,
    users_json,
    api_keys_json,
    api_response,
    directory_listing,
    random_server_header,
)
from wordlists import get_wordlists
from deception_responses import (
    detect_and_respond_deception,
    generate_sql_error_response,
    get_sql_response_with_data,
    detect_xss_pattern,
    generate_xss_response,
    generate_server_error,
)
from models import AccessLog
from ip_utils import is_valid_public_ip
from sqlalchemy import distinct


class Handler(BaseHTTPRequestHandler):
    """HTTP request handler for the deception server"""

    webpages: Optional[List[str]] = None
    config: Config = None
    tracker: AccessTracker = None
    counter: int = 0
    app_logger: logging.Logger = None
    access_logger: logging.Logger = None
    credential_logger: logging.Logger = None

    def _get_client_ip(self) -> str:
        """Extract client IP address from request, checking proxy headers first"""
        # Headers might not be available during early error logging
        if hasattr(self, "headers") and self.headers:
            # Check X-Forwarded-For header (set by load balancers/proxies)
            forwarded_for = self.headers.get("X-Forwarded-For")
            if forwarded_for:
                # X-Forwarded-For can contain multiple IPs, get the first (original client)
                return forwarded_for.split(",")[0].strip()

            # Check X-Real-IP header (set by nginx and other proxies)
            real_ip = self.headers.get("X-Real-IP")
            if real_ip:
                return real_ip.strip()

        # Fallback to direct connection IP
        return self.client_address[0]

    def _build_raw_request(self, body: str = "") -> str:
        """Build raw HTTP request string for forensic analysis"""
        try:
            # Request line
            raw = f"{self.command} {self.path} {self.request_version}\r\n"

            # Headers
            if hasattr(self, "headers") and self.headers:
                for header, value in self.headers.items():
                    raw += f"{header}: {value}\r\n"

            raw += "\r\n"

            # Body (if present)
            if body:
                raw += body

            return raw
        except Exception as e:
            # Fallback to minimal representation if building fails
            return f"{self.command} {self.path} (error building full request: {str(e)})"

    def _get_category_by_ip(self, client_ip: str) -> str:
        """Get the category of an IP from the database"""
        return self.tracker.get_category_by_ip(client_ip)

    def _get_page_visit_count(self, client_ip: str) -> int:
        """Get current page visit count for an IP"""
        return self.tracker.get_page_visit_count(client_ip)

    def _increment_page_visit(self, client_ip: str) -> int:
        """Increment page visit counter for an IP and return new count"""
        return self.tracker.increment_page_visit(client_ip)

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

    def _handle_sql_endpoint(self, path: str) -> bool:
        """
        Handle SQL injection honeypot endpoints.
        Returns True if the path was handled, False otherwise.
        """
        # SQL-vulnerable endpoints
        sql_endpoints = ["/api/search", "/api/sql", "/api/database"]

        base_path = urlparse(path).path
        if base_path not in sql_endpoints:
            return False

        try:
            parsed_url = urlparse(path)
            request_query = parsed_url.query

            # Log SQL injection attempt
            client_ip = self._get_client_ip()
            user_agent = self.headers.get("User-Agent", "")

            # Always check for SQL injection patterns
            error_msg, content_type, status_code = generate_sql_error_response(
                request_query or ""
            )

            if error_msg:
                # SQL injection detected - log and return error
                self.access_logger.warning(
                    f"[SQL INJECTION DETECTED] {client_ip} - {base_path} - Query: {request_query[:100] if request_query else 'empty'}"
                )
                self.send_response(status_code)
                self.send_header("Content-type", content_type)
                self.end_headers()
                self.wfile.write(error_msg.encode())
            else:
                # No injection detected - return fake data
                self.access_logger.info(
                    f"[SQL ENDPOINT] {client_ip} - {base_path} - Query: {request_query[:100] if request_query else 'empty'}"
                )
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                response_data = get_sql_response_with_data(
                    base_path, request_query or ""
                )
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
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Internal server error"}')
            except:
                pass
            return True

    def _handle_deception_response(
        self, path: str, query: str = "", body: str = "", method: str = "GET"
    ) -> bool:
        """
        Handle deception responses for path traversal, XXE, and command injection.
        Returns True if a deception response was sent, False otherwise.
        """
        try:
            self.app_logger.debug(f"Checking deception for: {method} {path}")
            result = detect_and_respond_deception(path, query, body, method)

            if result:
                response_body, content_type, status_code = result
                client_ip = self._get_client_ip()
                user_agent = self.headers.get("User-Agent", "")

                # Determine attack type using standardized names from wordlists
                full_input = f"{path} {query} {body}".lower()
                attack_type_db = None  # For database (standardized)
                attack_type_log = "UNKNOWN"  # For logging (human-readable)

                if (
                    "passwd" in path.lower()
                    or "shadow" in path.lower()
                    or ".." in path
                    or ".." in query
                ):
                    attack_type_db = "path_traversal"
                    attack_type_log = "PATH_TRAVERSAL"
                elif body and ("<!DOCTYPE" in body or "<!ENTITY" in body):
                    attack_type_db = "xxe_injection"
                    attack_type_log = "XXE_INJECTION"
                elif any(
                    pattern in full_input
                    for pattern in [
                        "cmd=",
                        "exec=",
                        "command=",
                        "execute=",
                        "system=",
                        ";",
                        "|",
                        "&&",
                        "whoami",
                        "id",
                        "uname",
                        "cat",
                        "ls",
                        "pwd",
                    ]
                ):
                    attack_type_db = "command_injection"
                    attack_type_log = "COMMAND_INJECTION"

                # Log the attack
                self.access_logger.warning(
                    f"[{attack_type_log} DETECTED] {client_ip} - {path[:100]} - Method: {method}"
                )

                # Record access before responding (deception returns early)
                self.tracker.record_access(
                    ip=client_ip,
                    path=path,
                    user_agent=user_agent,
                    body=body,
                    method=method,
                    raw_request=self._build_raw_request(body),
                )

                # Send the deception response
                self.send_response(status_code)
                self.send_header("Content-type", content_type)
                self.end_headers()
                self.wfile.write(response_body.encode())
                return True

        except BrokenPipeError:
            return True
        except Exception as e:
            self.app_logger.error(
                f"Error handling deception response for {path}: {str(e)}"
            )

        return False

    def generate_page(self, seed: str, page_visit_count: int) -> str:
        """Generate a webpage containing random links or canary token"""

        random.seed(seed)
        num_pages = random.randint(*self.config.links_per_page_range)

        # Check if this is a good crawler by IP category from database
        ip_category = self._get_category_by_ip(self._get_client_ip())

        # Determine if we should apply crawler page limit based on config and IP category
        should_apply_crawler_limit = False
        if self.config.infinite_pages_for_malicious:
            if (
                ip_category == "good_crawler" or ip_category == "regular_user"
            ) and page_visit_count >= self.config.max_pages_limit:
                should_apply_crawler_limit = True
        else:
            if (
                ip_category == "good_crawler"
                or ip_category == "bad_crawler"
                or ip_category == "attacker"
            ) and page_visit_count >= self.config.max_pages_limit:
                should_apply_crawler_limit = True

        # If good crawler reached max pages, return a simple page with no links
        if should_apply_crawler_limit:
            return html_templates.main_page(
                Handler.counter, "<p>Crawl limit reached.</p>"
            )

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
                address = "".join(
                    [
                        random.choice(self.config.char_space)
                        for _ in range(random.randint(*self.config.links_length_range))
                    ]
                )
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
        user_agent = self.headers.get("User-Agent", "")
        post_data = ""

        base_path = urlparse(self.path).path

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            post_data = self.rfile.read(content_length).decode(
                "utf-8", errors="replace"
            )

        parsed_url = urlparse(self.path)
        query_string = parsed_url.query

        if self._handle_deception_response(self.path, query_string, post_data, "POST"):
            return

        if base_path in ["/api/search", "/api/sql", "/api/database"]:
            self.access_logger.info(
                f"[SQL ENDPOINT POST] {client_ip} - {base_path} - Data: {post_data[:100] if post_data else 'empty'}"
            )

            error_msg, content_type, status_code = generate_sql_error_response(
                post_data
            )

            try:
                if error_msg:
                    self.access_logger.warning(
                        f"[SQL INJECTION DETECTED POST] {client_ip} - {base_path}"
                    )
                    self.send_response(status_code)
                    self.send_header("Content-type", content_type)
                    self.end_headers()
                    self.wfile.write(error_msg.encode())
                else:
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    response_data = get_sql_response_with_data(base_path, post_data)
                    self.wfile.write(response_data.encode())
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error in SQL POST handler: {str(e)}")
            return

        if base_path == "/api/contact":
            # Parse URL-encoded POST data properly
            parsed_data = {}
            if post_data:
                # Use parse_qs for proper URL decoding
                parsed_qs = parse_qs(post_data)
                # parse_qs returns lists, get first value of each
                parsed_data = {k: v[0] if v else "" for k, v in parsed_qs.items()}

            self.app_logger.debug(f"Parsed contact data: {parsed_data}")

            xss_detected = any(detect_xss_pattern(str(v)) for v in parsed_data.values())

            if xss_detected:
                self.access_logger.warning(
                    f"[XSS ATTEMPT DETECTED] {client_ip} - {base_path} - Data: {post_data[:200]}"
                )
            else:
                self.access_logger.info(
                    f"[XSS ENDPOINT POST] {client_ip} - {base_path}"
                )

            # Record access for dashboard tracking (including XSS detection)
            self.tracker.record_access(
                ip=client_ip,
                path=self.path,
                user_agent=user_agent,
                body=post_data,
                method="POST",
                raw_request=self._build_raw_request(post_data),
            )

            try:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                response_html = generate_xss_response(parsed_data)
                self.wfile.write(response_html.encode())
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error in XSS POST handler: {str(e)}")
            return

        self.access_logger.warning(
            f"[LOGIN ATTEMPT] {client_ip} - {self.path} - {user_agent[:50]}"
        )

        # post_data was already read at the beginning of do_POST, don't read again
        if post_data:
            self.access_logger.warning(f"[POST DATA] {post_data[:200]}")

            # Parse and log credentials
            username, password = self.tracker.parse_credentials(post_data)
            if username or password:
                # Log to dedicated credentials.log file
                timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
                credential_line = f"{timestamp}|{client_ip}|{username or 'N/A'}|{password or 'N/A'}|{self.path}"
                self.credential_logger.info(credential_line)

                # Also record in tracker for dashboard
                self.tracker.record_credential_attempt(
                    client_ip, self.path, username or "N/A", password or "N/A"
                )

                self.access_logger.warning(
                    f"[CREDENTIALS CAPTURED] {client_ip} - Username: {username or 'N/A'} - Path: {self.path}"
                )

        # send the post data (body) to the record_access function so the post data can be used to detect suspicious things.
        self.tracker.record_access(
            client_ip,
            self.path,
            user_agent,
            post_data,
            method="POST",
            raw_request=self._build_raw_request(post_data),
        )

        time.sleep(1)

        try:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
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
            if path == "/robots.txt":
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(html_templates.robots_txt().encode())
                return True

            if path in ["/credentials.txt", "/passwords.txt", "/admin_notes.txt"]:
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                if "credentials" in path:
                    self.wfile.write(credentials_txt().encode())
                else:
                    self.wfile.write(passwords_txt().encode())
                return True

            if path in ["/users.json", "/api_keys.json", "/config.json"]:
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                if "users" in path:
                    self.wfile.write(users_json().encode())
                elif "api_keys" in path:
                    self.wfile.write(api_keys_json().encode())
                else:
                    self.wfile.write(api_response("/api/config").encode())
                return True

            if path in ["/admin", "/admin/", "/admin/login", "/login"]:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(html_templates.login_form().encode())
                return True

            if path in ["/users", "/user", "/database", "/db", "/search"]:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(html_templates.product_search().encode())
                return True

            if path in ["/info", "/input", "/contact", "/feedback", "/comment"]:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(html_templates.input_form().encode())
                return True

            if path == "/server":
                error_html, content_type = generate_server_error()
                self.send_response(500)
                self.send_header("Content-type", content_type)
                self.end_headers()
                self.wfile.write(error_html.encode())
                return True

            if path in ["/wp-login.php", "/wp-login", "/wp-admin", "/wp-admin/"]:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(html_templates.wp_login().encode())
                return True

            if path in ["/wp-content/", "/wp-includes/"] or "wordpress" in path.lower():
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(html_templates.wordpress().encode())
                return True

            if "phpmyadmin" in path.lower() or path in ["/pma/", "/phpMyAdmin/"]:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(html_templates.phpmyadmin().encode())
                return True

            if path.startswith("/api/") or path.startswith("/api") or path in ["/.env"]:
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(api_response(path).encode())
                return True

            if path in [
                "/backup/",
                "/uploads/",
                "/private/",
                "/admin/",
                "/config/",
                "/database/",
            ]:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
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

        # respond with HTTP error code if client is banned
        if self.tracker.is_banned_ip(client_ip):
            self.send_response(500)
            self.end_headers()
            return

        # get request data
        user_agent = self.headers.get("User-Agent", "")
        request_path = urlparse(self.path).path
        self.app_logger.info(f"request_query: {request_path}")
        parsed_url = urlparse(self.path)
        query_string = parsed_url.query
        query_params = parse_qs(query_string)
        self.app_logger.info(f"query_params: {query_params}")

        if self._handle_deception_response(self.path, query_string, "", "GET"):
            return

        # get database reference
        db = get_database()
        session = db.session

        # Handle static files for dashboard
        if self.config.dashboard_secret_path and self.path.startswith(
            f"{self.config.dashboard_secret_path}/static/"
        ):

            file_path = self.path.replace(
                f"{self.config.dashboard_secret_path}/static/", ""
            )
            static_dir = os.path.join(os.path.dirname(__file__), "templates", "static")
            full_path = os.path.join(static_dir, file_path)

            # Security check: ensure the path is within static directory
            if os.path.commonpath(
                [full_path, static_dir]
            ) == static_dir and os.path.exists(full_path):
                try:
                    with open(full_path, "rb") as f:
                        content = f.read()
                    self.send_response(200)
                    if file_path.endswith(".svg"):
                        self.send_header("Content-type", "image/svg+xml")
                    elif file_path.endswith(".css"):
                        self.send_header("Content-type", "text/css")
                    elif file_path.endswith(".js"):
                        self.send_header("Content-type", "application/javascript")
                    else:
                        self.send_header("Content-type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                    return
                except Exception as e:
                    self.app_logger.error(f"Error serving static file: {e}")

            self.send_response(404)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not found")
            return

        if (
            self.config.dashboard_secret_path
            and self.path == self.config.dashboard_secret_path
        ):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            try:
                stats = self.tracker.get_stats()
                self.wfile.write(
                    generate_dashboard(
                        stats, self.config.dashboard_secret_path
                    ).encode()
                )
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error generating dashboard: {e}")
            return

        # API endpoint for fetching all IP statistics
        if (
            self.config.dashboard_secret_path
            and self.path == f"{self.config.dashboard_secret_path}/api/all-ip-stats"
        ):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header(
                "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
            )
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            try:

                ip_stats_list = db.get_ip_stats(limit=500)
                self.wfile.write(json.dumps({"ips": ip_stats_list}).encode())
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error fetching all IP stats: {e}")
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return

        # API endpoint for fetching paginated attackers
        if self.config.dashboard_secret_path and self.path.startswith(
            f"{self.config.dashboard_secret_path}/api/attackers"
        ):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header(
                "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
            )
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            try:

                page = int(query_params.get("page", ["1"])[0])
                page_size = int(query_params.get("page_size", ["25"])[0])
                sort_by = query_params.get("sort_by", ["total_requests"])[0]
                sort_order = query_params.get("sort_order", ["desc"])[0]

                # Ensure valid parameters
                page = max(1, page)
                page_size = min(max(1, page_size), 100)  # Max 100 per page

                result = db.get_attackers_paginated(
                    page=page,
                    page_size=page_size,
                    sort_by=sort_by,
                    sort_order=sort_order,
                )
                self.wfile.write(json.dumps(result).encode())
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error fetching attackers: {e}")
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return

        # API endpoint for fetching all IPs (all categories)
        if self.config.dashboard_secret_path and self.path.startswith(
            f"{self.config.dashboard_secret_path}/api/all-ips"
        ):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header(
                "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
            )
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            try:

                # Parse query parameters
                parsed_url = urlparse(self.path)
                query_params = parse_qs(parsed_url.query)
                page = int(query_params.get("page", ["1"])[0])
                page_size = int(query_params.get("page_size", ["25"])[0])
                sort_by = query_params.get("sort_by", ["total_requests"])[0]
                sort_order = query_params.get("sort_order", ["desc"])[0]

                # Ensure valid parameters
                page = max(1, page)
                page_size = min(max(1, page_size), 100)  # Max 100 per page

                result = db.get_all_ips_paginated(
                    page=page,
                    page_size=page_size,
                    sort_by=sort_by,
                    sort_order=sort_order,
                )
                self.wfile.write(json.dumps(result).encode())
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error fetching all IPs: {e}")
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return

        # API endpoint for fetching IP stats
        if self.config.dashboard_secret_path and self.path.startswith(
            f"{self.config.dashboard_secret_path}/api/ip-stats/"
        ):
            ip_address = self.path.replace(
                f"{self.config.dashboard_secret_path}/api/ip-stats/", ""
            )
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            # Prevent browser caching - force fresh data from database every time
            self.send_header(
                "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
            )
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            try:

                ip_stats = db.get_ip_stats_by_ip(ip_address)
                if ip_stats:
                    self.wfile.write(json.dumps(ip_stats).encode())
                else:
                    self.wfile.write(json.dumps({"error": "IP not found"}).encode())
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error fetching IP stats: {e}")
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return

        # API endpoint for paginated honeypot triggers
        if self.config.dashboard_secret_path and self.path.startswith(
            f"{self.config.dashboard_secret_path}/api/honeypot"
        ):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header(
                "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
            )
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            try:

                parsed_url = urlparse(self.path)
                query_params = parse_qs(parsed_url.query)
                page = int(query_params.get("page", ["1"])[0])
                page_size = int(query_params.get("page_size", ["5"])[0])
                sort_by = query_params.get("sort_by", ["count"])[0]
                sort_order = query_params.get("sort_order", ["desc"])[0]

                page = max(1, page)
                page_size = min(max(1, page_size), 100)

                result = db.get_honeypot_paginated(
                    page=page,
                    page_size=page_size,
                    sort_by=sort_by,
                    sort_order=sort_order,
                )
                self.wfile.write(json.dumps(result).encode())
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error fetching honeypot data: {e}")
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return

        # API endpoint for paginated credentials
        if self.config.dashboard_secret_path and self.path.startswith(
            f"{self.config.dashboard_secret_path}/api/credentials"
        ):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header(
                "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
            )
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            try:

                parsed_url = urlparse(self.path)
                query_params = parse_qs(parsed_url.query)
                page = int(query_params.get("page", ["1"])[0])
                page_size = int(query_params.get("page_size", ["5"])[0])
                sort_by = query_params.get("sort_by", ["timestamp"])[0]
                sort_order = query_params.get("sort_order", ["desc"])[0]

                page = max(1, page)
                page_size = min(max(1, page_size), 100)

                result = db.get_credentials_paginated(
                    page=page,
                    page_size=page_size,
                    sort_by=sort_by,
                    sort_order=sort_order,
                )
                self.wfile.write(json.dumps(result).encode())
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error fetching credentials: {e}")
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return

        # API endpoint for paginated top IPs
        if self.config.dashboard_secret_path and self.path.startswith(
            f"{self.config.dashboard_secret_path}/api/top-ips"
        ):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header(
                "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
            )
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            try:

                parsed_url = urlparse(self.path)
                query_params = parse_qs(parsed_url.query)
                page = int(query_params.get("page", ["1"])[0])
                page_size = int(query_params.get("page_size", ["5"])[0])
                sort_by = query_params.get("sort_by", ["count"])[0]
                sort_order = query_params.get("sort_order", ["desc"])[0]

                page = max(1, page)
                page_size = min(max(1, page_size), 100)

                result = db.get_top_ips_paginated(
                    page=page,
                    page_size=page_size,
                    sort_by=sort_by,
                    sort_order=sort_order,
                )
                self.wfile.write(json.dumps(result).encode())
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error fetching top IPs: {e}")
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return

        # API endpoint for paginated top paths
        if self.config.dashboard_secret_path and self.path.startswith(
            f"{self.config.dashboard_secret_path}/api/top-paths"
        ):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header(
                "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
            )
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            try:

                parsed_url = urlparse(self.path)
                query_params = parse_qs(parsed_url.query)
                page = int(query_params.get("page", ["1"])[0])
                page_size = int(query_params.get("page_size", ["5"])[0])
                sort_by = query_params.get("sort_by", ["count"])[0]
                sort_order = query_params.get("sort_order", ["desc"])[0]

                page = max(1, page)
                page_size = min(max(1, page_size), 100)

                result = db.get_top_paths_paginated(
                    page=page,
                    page_size=page_size,
                    sort_by=sort_by,
                    sort_order=sort_order,
                )
                self.wfile.write(json.dumps(result).encode())
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error fetching top paths: {e}")
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return

        # API endpoint for paginated top user agents
        if self.config.dashboard_secret_path and self.path.startswith(
            f"{self.config.dashboard_secret_path}/api/top-user-agents"
        ):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header(
                "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
            )
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            try:

                parsed_url = urlparse(self.path)
                query_params = parse_qs(parsed_url.query)
                page = int(query_params.get("page", ["1"])[0])
                page_size = int(query_params.get("page_size", ["5"])[0])
                sort_by = query_params.get("sort_by", ["count"])[0]
                sort_order = query_params.get("sort_order", ["desc"])[0]

                page = max(1, page)
                page_size = min(max(1, page_size), 100)

                result = db.get_top_user_agents_paginated(
                    page=page,
                    page_size=page_size,
                    sort_by=sort_by,
                    sort_order=sort_order,
                )
                self.wfile.write(json.dumps(result).encode())
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error fetching top user agents: {e}")
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return

        # API endpoint for paginated attack types
        if self.config.dashboard_secret_path and self.path.startswith(
            f"{self.config.dashboard_secret_path}/api/attack-types"
        ):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header(
                "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
            )
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            try:

                parsed_url = urlparse(self.path)
                query_params = parse_qs(parsed_url.query)
                page = int(query_params.get("page", ["1"])[0])
                page_size = int(query_params.get("page_size", ["5"])[0])
                sort_by = query_params.get("sort_by", ["timestamp"])[0]
                sort_order = query_params.get("sort_order", ["desc"])[0]

                page = max(1, page)
                page_size = min(max(1, page_size), 100)

                result = db.get_attack_types_paginated(
                    page=page,
                    page_size=page_size,
                    sort_by=sort_by,
                    sort_order=sort_order,
                )
                self.wfile.write(json.dumps(result).encode())
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error fetching attack types: {e}")
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return

        # API endpoint for attack types statistics (aggregated)
        if self.config.dashboard_secret_path and self.path.startswith(
            f"{self.config.dashboard_secret_path}/api/attack-types-stats"
        ):
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header(
                "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
            )
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            try:
                parsed_url = urlparse(self.path)
                query_params = parse_qs(parsed_url.query)
                limit = int(query_params.get("limit", ["20"])[0])
                limit = min(max(1, limit), 100)  # Cap at 100

                result = db.get_attack_types_stats(limit=limit)
                self.wfile.write(json.dumps(result).encode())
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error fetching attack types stats: {e}")
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return

        # API endpoint for fetching raw request by log ID
        if self.config.dashboard_secret_path and self.path.startswith(
            f"{self.config.dashboard_secret_path}/api/raw-request/"
        ):
            try:
                # Extract log ID from path: /api/raw-request/123
                log_id = int(self.path.split("/")[-1])
                raw_request = db.get_raw_request_by_id(log_id)

                if raw_request is None:
                    self.send_response(404)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(
                        json.dumps({"error": "Raw request not found"}).encode()
                    )
                else:
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header(
                        "Cache-Control",
                        "no-store, no-cache, must-revalidate, max-age=0",
                    )
                    self.end_headers()
                    self.wfile.write(json.dumps({"raw_request": raw_request}).encode())
            except (ValueError, IndexError):
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid log ID"}).encode())
            except Exception as e:
                self.app_logger.error(f"Error fetching raw request: {e}")
                self.send_response(500)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return

        # API endpoint for downloading malicious IPs blocklist file
        if (
            self.config.dashboard_secret_path
            and request_path == f"{self.config.dashboard_secret_path}/api/get_banlist"
        ):

            # get fwtype from request params
            fwtype = query_params.get("fwtype", ["iptables"])[0]
            filename = f"{fwtype}_banlist.txt"
            if fwtype == "raw":
                filename = f"malicious_ips.txt"

            file_path = os.path.join(self.config.exports_path, f"{filename}")

            try:
                if os.path.exists(file_path):
                    with open(file_path, "rb") as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header("Content-type", "text/plain")
                    self.send_header(
                        "Content-Disposition",
                        f'attachment; filename="{filename}"',
                    )
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                else:
                    self.send_response(404)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"File not found")
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error serving malicious IPs file: {e}")
                self.send_response(500)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Internal server error")
            return

        # API endpoint for downloading malicious IPs file
        if (
            self.config.dashboard_secret_path
            and self.path
            == f"{self.config.dashboard_secret_path}/api/download/malicious_ips.txt"
        ):

            file_path = os.path.join(
                os.path.dirname(__file__), "exports", "malicious_ips.txt"
            )
            try:
                if os.path.exists(file_path):
                    with open(file_path, "rb") as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header("Content-type", "text/plain")
                    self.send_header(
                        "Content-Disposition",
                        'attachment; filename="malicious_ips.txt"',
                    )
                    self.send_header("Content-Length", str(len(content)))
                    self.end_headers()
                    self.wfile.write(content)
                else:
                    self.send_response(404)
                    self.send_header("Content-type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"File not found")
            except BrokenPipeError:
                pass
            except Exception as e:
                self.app_logger.error(f"Error serving malicious IPs file: {e}")
                self.send_response(500)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Internal server error")
            return

        self.tracker.record_access(
            client_ip,
            self.path,
            user_agent,
            method="GET",
            raw_request=self._build_raw_request(),
        )

        if self.tracker.is_suspicious_user_agent(user_agent):
            self.access_logger.warning(
                f"[SUSPICIOUS] {client_ip} - {user_agent[:50]} - {self.path}"
            )

        if self._should_return_error():
            error_code = self._get_random_error_code()
            self.access_logger.info(
                f"Returning error {error_code} to {client_ip} - {self.path}"
            )
            self.send_response(error_code)
            self.end_headers()
            return

        if self.serve_special_path(self.path):
            return

        time.sleep(self.config.delay / 1000.0)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        try:
            # Increment page visit counter for this IP and get the current count
            current_visit_count = self._increment_page_visit(client_ip)
            self.wfile.write(
                self.generate_page(self.path, current_visit_count).encode()
            )

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
