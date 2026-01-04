#!/usr/bin/env python3
from sqlalchemy import select
from typing import Optional
from database import get_database, DatabaseManager
from zoneinfo import ZoneInfo
from pathlib import Path
from datetime import datetime, timedelta
import re
from wordlists import get_wordlists

"""
Functions for user activity analysis
"""

class Analyzer:
    """
    Analyzes users activity and produces aggregated insights
    """
    def __init__(self, db_manager: Optional[DatabaseManager] = None, timezone: Optional[ZoneInfo] = None):
        """
        Initialize the access tracker.

        Args:
            db_manager: Optional DatabaseManager for persistence.
                        If None, will use the global singleton.
        """
        self.timezone = timezone or ZoneInfo('UTC')

        # Database manager for persistence (lazily initialized)
        self._db_manager = db_manager
    
    @property
    def db(self) -> Optional[DatabaseManager]:
        """
        Get the database manager, lazily initializing if needed.

        Returns:
            DatabaseManager instance or None if not available
        """
        if self._db_manager is None:
            try:
                self._db_manager = get_database()
            except Exception:
                # Database not initialized, persistence disabled
                pass
        return self._db_manager
    
    def infer_user_category(self, ip: str) -> str:

        score = {}
        score["attacker"] = {"risky_http_methods": False, "robots_violations": False, "uneven_request_timing": False, "different_user_agents": False, "attack_url": False}
        score["good_crawler"] = {"risky_http_methods": False, "robots_violations": False, "uneven_request_timing": False, "different_user_agents": False, "attack_url": False}
        score["bad_crawler"] = {"risky_http_methods": False, "robots_violations": False, "uneven_request_timing": False, "different_user_agents": False, "attack_url": False}
        score["regular_user"] = {"risky_http_methods": False, "robots_violations": False, "uneven_request_timing": False, "different_user_agents": False, "attack_url": False}
        
        #1-3 low, 4-6 mid, 7-9 high, 10-20 extreme
        weights = {
            "attacker": {
                "risky_http_methods": 6,
                "robots_violations": 4,
                "uneven_request_timing": 5,
                "different_user_agents": 8,
                "attack_url": 15
            },
            "good_crawler": {
                "risky_http_methods": 0,
                "robots_violations": 0,
                "uneven_request_timing": 0,
                "different_user_agents": 0,
                "attack_url": 0
            },
            "bad_crawler": {
                "risky_http_methods": 2,
                "robots_violations": 4,
                "uneven_request_timing": 0,
                "different_user_agents": 5,
                "attack_url": 5
            },
            "regular_user": {
                "risky_http_methods": 0,
                "robots_violations": 0,
                "uneven_request_timing": 8,
                "different_user_agents": 3,
                "attack_url": 0
            }
        }


        accesses = self.db.get_access_logs(ip_filter = ip, limit=1000)
        total_accesses_count = len(accesses)
        if total_accesses_count <= 0:
            return

        #--------------------- HTTP Methods ---------------------


        get_accesses_count = len([item for item in accesses if item["method"] == "GET"])
        post_accesses_count = len([item for item in accesses if item["method"] == "POST"])
        put_accesses_count = len([item for item in accesses if item["method"] == "PUT"])
        delete_accesses_count = len([item for item in accesses if item["method"] == "DELETE"])
        head_accesses_count = len([item for item in accesses if item["method"] == "HEAD"])
        options_accesses_count = len([item for item in accesses if item["method"] == "OPTIONS"])
        patch_accesses_count = len([item for item in accesses if item["method"] == "PATCH"])
        #print(f"TOTAL: {total_accesses_count} - GET: {get_accesses_count} - POST: {post_accesses_count}")
        

        #if >5% attacker or bad crawler
        if total_accesses_count > 0:
            http_method_attacker_score = (post_accesses_count + put_accesses_count + delete_accesses_count + options_accesses_count + patch_accesses_count) / total_accesses_count
        else:
            http_method_attacker_score = 0

        #print(f"HTTP Method attacker score: {http_method_attacker_score}")
        if http_method_attacker_score > 0.2:
            score["attacker"]["risky_http_methods"] = True
            score["good_crawler"]["risky_http_methods"] = False
            score["bad_crawler"]["risky_http_methods"] = True
            score["regular_user"]["risky_http_methods"] = False
        else:
            score["attacker"]["risky_http_methods"] = False
            score["good_crawler"]["risky_http_methods"] = False
            score["bad_crawler"]["risky_http_methods"] = False
            score["regular_user"]["risky_http_methods"] = False
        
        #print(f"Updated score: {score}")



        #--------------------- Robots Violations ---------------------
        #respect robots.txt and login/config pages access frequency
        robots_disallows = []
        robots_path = config_path = Path(__file__).parent / "templates" / "html" / "robots.txt"
        with open(robots_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(":")
                
                if parts[0] == "Disallow":
                    parts[1] = parts[1].rstrip("/")
                    #print(f"DISALLOW {parts[1]}")
                    robots_disallows.append(parts[1].strip())

        #if 0 100% sure is good crawler, if >10% of robots violated is bad crawler or attacker
        violated_robots_count = len([item for item in accesses if item["path"].rstrip("/") in tuple(robots_disallows)])
        #print(f"Violated robots count: {violated_robots_count}")
        if total_accesses_count > 0:
            violated_robots_ratio = violated_robots_count / total_accesses_count
        else:
            violated_robots_ratio = 0

        if violated_robots_ratio > 0.10:
            score["attacker"]["robots_violations"] = True
            score["good_crawler"]["robots_violations"] = False
            score["bad_crawler"]["robots_violations"] = True
            score["regular_user"]["robots_violations"] = False
        else:
            score["attacker"]["robots_violations"] = True
            score["good_crawler"]["robots_violations"] = False
            score["bad_crawler"]["robots_violations"] = True
            score["regular_user"]["robots_violations"] = False
        
        #--------------------- Requests Timing ---------------------
        #Request rate and timing: steady, throttled, polite vs attackers' bursty, aggressive, or oddly rhythmic behavior
        timestamps = [datetime.fromisoformat(item["timestamp"]) for item in accesses]
        print(f"Timestamps #: {len(timestamps)}")
        timestamps = [ts for ts in timestamps if datetime.utcnow() - ts <= timedelta(minutes=5)]
        print(f"Timestamps #: {len(timestamps)}")
        timestamps = sorted(timestamps, reverse=True)
        print(f"Timestamps #: {len(timestamps)}")

        time_diffs = []
        for i in range(0, len(timestamps)-1):
            diff = (timestamps[i] - timestamps[i+1]).total_seconds()
            time_diffs.append(diff)
        
        print(f"Time diffs: {time_diffs}")
        
        mean = 0
        variance = 0
        std = 0
        cv = 0
        if time_diffs:
            mean = sum(time_diffs) / len(time_diffs)
            variance = sum((x - mean) ** 2 for x in time_diffs) / len(time_diffs)
            std = variance ** 0.5
            cv = std/mean
            print(f"Mean: {mean} - Variance {variance} - Standard Deviation {std} - Coefficient of Variation: {cv}")

        if mean > 4:
            score["attacker"]["uneven_request_timing"] = True
            score["good_crawler"]["uneven_request_timing"] = False
            score["bad_crawler"]["uneven_request_timing"] = False
            score["regular_user"]["uneven_request_timing"] = True
        else:
            score["attacker"]["uneven_request_timing"] = True
            score["good_crawler"]["uneven_request_timing"] = False
            score["bad_crawler"]["uneven_request_timing"] = True
            score["regular_user"]["uneven_request_timing"] = False


        #--------------------- Different User Agents ---------------------
        #Header Quality and Consistency: Crawlers tend to use complete and consistent headers, attackers might miss, fake, or change headers
        user_agents_used = [item["user_agent"] for item in accesses]
        user_agents_used = list(dict.fromkeys(user_agents_used))
        #print(f"User agents used: {user_agents_used}")

        if len(user_agents_used)> 4:
            score["attacker"]["different_user_agents"] = True
            score["good_crawler"]["different_user_agents"] = False
            score["bad_crawler"]["different_user_agentss"] = True
            score["regular_user"]["different_user_agents"] = False
        else:
            score["attacker"]["different_user_agents"] = True
            score["good_crawler"]["different_user_agents"] = False
            score["bad_crawler"]["different_user_agents"] = True
            score["regular_user"]["different_user_agents"] = False

        #--------------------- Attack URLs ---------------------

        attack_url_found = False
        # attack_types = {
        #     'path_traversal': r'\.\.',
        #     'sql_injection': r"('|--|;|\bOR\b|\bUNION\b|\bSELECT\b|\bDROP\b)",
        #     'xss_attempt': r'(<script|javascript:|onerror=|onload=)',
        #     'shell_injection': r'(\||;|`|\$\(|&&)'
        # }

        wl = get_wordlists()
        if wl.attack_urls:
            queried_paths = [item["path"] for item in accesses]

            for queried_path in queried_paths:
                #print(f"QUERIED PATH: {queried_path}")
                for name, pattern in wl.attack_urls.items():
                    #print(f"Pattern: {pattern}")
                    if re.search(pattern, queried_path, re.IGNORECASE):
                        attack_url_found = True
            
            if attack_url_found:
                score["attacker"]["attack_url"] = True
                score["good_crawler"]["attack_url"] = False
                score["bad_crawler"]["attack_url"] = False
                score["regular_user"]["attack_url"] = False
            else:
                score["attacker"]["attack_url"] = False
                score["good_crawler"]["attack_url"] = False
                score["bad_crawler"]["attack_url"] = False
                score["regular_user"]["attack_url"] = False

        #--------------------- Calculate score ---------------------

        attacker_score = score["attacker"]["risky_http_methods"] * weights["attacker"]["risky_http_methods"]
        attacker_score = attacker_score + score["attacker"]["robots_violations"] * weights["attacker"]["robots_violations"]
        attacker_score = attacker_score + score["attacker"]["uneven_request_timing"] * weights["attacker"]["uneven_request_timing"]
        attacker_score = attacker_score + score["attacker"]["different_user_agents"] * weights["attacker"]["different_user_agents"]
        attacker_score = attacker_score + score["attacker"]["attack_url"] * weights["attacker"]["attack_url"]

        good_crawler_score = score["good_crawler"]["risky_http_methods"] * weights["good_crawler"]["risky_http_methods"]
        good_crawler_score = good_crawler_score + score["good_crawler"]["robots_violations"] * weights["good_crawler"]["robots_violations"]
        good_crawler_score = good_crawler_score + score["good_crawler"]["uneven_request_timing"] * weights["good_crawler"]["uneven_request_timing"]
        good_crawler_score = good_crawler_score + score["good_crawler"]["different_user_agents"] * weights["good_crawler"]["different_user_agents"]
        good_crawler_score = good_crawler_score + score["good_crawler"]["attack_url"] * weights["good_crawler"]["attack_url"]

        bad_crawler_score = score["bad_crawler"]["risky_http_methods"] * weights["bad_crawler"]["risky_http_methods"]
        bad_crawler_score = bad_crawler_score + score["bad_crawler"]["robots_violations"] * weights["bad_crawler"]["robots_violations"]
        bad_crawler_score = bad_crawler_score + score["bad_crawler"]["uneven_request_timing"] * weights["bad_crawler"]["uneven_request_timing"]
        bad_crawler_score = bad_crawler_score + score["bad_crawler"]["different_user_agents"] * weights["bad_crawler"]["different_user_agents"]
        bad_crawler_score = bad_crawler_score + score["bad_crawler"]["attack_url"] * weights["bad_crawler"]["attack_url"]

        regular_user_score = score["regular_user"]["risky_http_methods"] * weights["regular_user"]["risky_http_methods"]
        regular_user_score = regular_user_score + score["regular_user"]["robots_violations"] * weights["regular_user"]["robots_violations"]
        regular_user_score = regular_user_score + score["regular_user"]["uneven_request_timing"] * weights["regular_user"]["uneven_request_timing"]
        regular_user_score = regular_user_score + score["regular_user"]["different_user_agents"] * weights["regular_user"]["different_user_agents"]
        regular_user_score = regular_user_score + score["regular_user"]["attack_url"] * weights["regular_user"]["attack_url"]

        #print(f"Attacker score: {attacker_score}")
        #print(f"Good Crawler score: {good_crawler_score}")
        #print(f"Bad Crawler score: {bad_crawler_score}")
        #print(f"Regular User score: {regular_user_score}")

        analyzed_metrics = {"risky_http_methods": http_method_attacker_score, "robots_violations": violated_robots_ratio, "uneven_request_timing": mean, "different_user_agents": user_agents_used, "attack_url": attack_url_found}
        category_scores = {"attacker": attacker_score, "good_crawler": good_crawler_score, "bad_crawler": bad_crawler_score, "regular_user": regular_user_score}
        category = max(category_scores, key=category_scores.get)
        last_analysis = datetime.utcnow()

        self._db_manager.update_ip_stats_analysis(ip, analyzed_metrics, category, category_scores, last_analysis)

        return 0
