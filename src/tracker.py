#!/usr/bin/env python3

from typing import Dict, List, Tuple
from collections import defaultdict
from datetime import datetime


class AccessTracker:
    """Track IP addresses and paths accessed"""
    def __init__(self):
        self.ip_counts: Dict[str, int] = defaultdict(int)
        self.path_counts: Dict[str, int] = defaultdict(int)
        self.user_agent_counts: Dict[str, int] = defaultdict(int)
        self.access_log: List[Dict] = []
        self.suspicious_patterns = [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python-requests',
            'scanner', 'nikto', 'sqlmap', 'nmap', 'masscan', 'nessus', 'acunetix',
            'burp', 'zap', 'w3af', 'metasploit', 'nuclei', 'gobuster', 'dirbuster'
        ]
        # Track IPs that accessed honeypot paths from robots.txt
        self.honeypot_triggered: Dict[str, List[str]] = defaultdict(list)

    def record_access(self, ip: str, path: str, user_agent: str = ''):
        """Record an access attempt"""
        self.ip_counts[ip] += 1
        self.path_counts[path] += 1
        if user_agent:
            self.user_agent_counts[user_agent] += 1
        
        is_suspicious = self.is_suspicious_user_agent(user_agent) or self.is_honeypot_path(path)
        
        # Track if this IP accessed a honeypot path
        if self.is_honeypot_path(path):
            self.honeypot_triggered[ip].append(path)
        
        self.access_log.append({
            'ip': ip,
            'path': path,
            'user_agent': user_agent,
            'suspicious': is_suspicious,
            'honeypot_triggered': self.is_honeypot_path(path),
            'timestamp': datetime.now().isoformat()
        })

    def is_honeypot_path(self, path: str) -> bool:
        """Check if path is one of the honeypot traps from robots.txt"""
        honeypot_paths = [
            '/admin',
            '/admin/',
            '/backup',
            '/backup/',
            '/config',
            '/config/',
            '/private',
            '/private/',
            '/database',
            '/database/',
            '/credentials.txt',
            '/passwords.txt',
            '/admin_notes.txt',
            '/api_keys.json',
            '/.env',
            '/wp-admin',
            '/wp-admin/',
            '/phpmyadmin',
            '/phpMyAdmin/'
        ]
        return path in honeypot_paths or any(hp in path.lower() for hp in ['/backup', '/admin', '/config', '/private', '/database', 'phpmyadmin'])

    def is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent matches suspicious patterns"""
        if not user_agent:
            return True
        ua_lower = user_agent.lower()
        return any(pattern in ua_lower for pattern in self.suspicious_patterns)

    def get_top_ips(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top N IP addresses by access count"""
        return sorted(self.ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

    def get_top_paths(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top N paths by access count"""
        return sorted(self.path_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

    def get_top_user_agents(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top N user agents by access count"""
        return sorted(self.user_agent_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

    def get_suspicious_accesses(self, limit: int = 20) -> List[Dict]:
        """Get recent suspicious accesses"""
        suspicious = [log for log in self.access_log if log.get('suspicious', False)]
        return suspicious[-limit:]

    def get_honeypot_triggered_ips(self) -> List[Tuple[str, List[str]]]:
        """Get IPs that accessed honeypot paths"""
        return [(ip, paths) for ip, paths in self.honeypot_triggered.items()]

    def get_stats(self) -> Dict:
        """Get statistics summary"""
        suspicious_count = sum(1 for log in self.access_log if log.get('suspicious', False))
        honeypot_count = sum(1 for log in self.access_log if log.get('honeypot_triggered', False))
        return {
            'total_accesses': len(self.access_log),
            'unique_ips': len(self.ip_counts),
            'unique_paths': len(self.path_counts),
            'suspicious_accesses': suspicious_count,
            'honeypot_triggered': honeypot_count,
            'honeypot_ips': len(self.honeypot_triggered),
            'top_ips': self.get_top_ips(10),
            'top_paths': self.get_top_paths(10),
            'top_user_agents': self.get_top_user_agents(10),
            'recent_suspicious': self.get_suspicious_accesses(20),
            'honeypot_triggered_ips': self.get_honeypot_triggered_ips()
        }
