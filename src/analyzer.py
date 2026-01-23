#!/usr/bin/env python3
from sqlalchemy import select
from typing import Optional
from database import get_database, DatabaseManager
from zoneinfo import ZoneInfo
from pathlib import Path
from datetime import datetime, timedelta
import re
import urllib.parse
from wordlists import get_wordlists
from config import get_config
from logger import get_app_logger
import requests
from sanitizer import sanitize_for_storage, sanitize_dict

"""
Functions for user activity analysis
"""

app_logger = get_app_logger()


class Analyzer:
    """
    Analyzes users activity and produces aggregated insights
    """

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        """
        Initialize the access tracker.

        Args:
            db_manager: Optional DatabaseManager for persistence.
                        If None, will use the global singleton.
        """

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

    # def infer_user_category(self, ip: str) -> str:

    #     config = get_config()

    #     http_risky_methods_threshold = config.http_risky_methods_threshold
    #     violated_robots_threshold = config.violated_robots_threshold
    #     uneven_request_timing_threshold = config.uneven_request_timing_threshold
    #     user_agents_used_threshold = config.user_agents_used_threshold
    #     attack_urls_threshold = config.attack_urls_threshold
    #     uneven_request_timing_time_window_seconds = config.uneven_request_timing_time_window_seconds

    #     app_logger.debug(f"http_risky_methods_threshold: {http_risky_methods_threshold}")

    #     score = {}
    #     score["attacker"] = {"risky_http_methods": False, "robots_violations": False, "uneven_request_timing": False, "different_user_agents": False, "attack_url": False}
    #     score["good_crawler"] = {"risky_http_methods": False, "robots_violations": False, "uneven_request_timing": False, "different_user_agents": False, "attack_url": False}
    #     score["bad_crawler"] = {"risky_http_methods": False, "robots_violations": False, "uneven_request_timing": False, "different_user_agents": False, "attack_url": False}
    #     score["regular_user"] = {"risky_http_methods": False, "robots_violations": False, "uneven_request_timing": False, "different_user_agents": False, "attack_url": False}

    #     #1-3 low, 4-6 mid, 7-9 high, 10-20 extreme
    #     weights = {
    #         "attacker": {
    #             "risky_http_methods": 6,
    #             "robots_violations": 4,
    #             "uneven_request_timing": 3,
    #             "different_user_agents": 8,
    #             "attack_url": 15
    #         },
    #         "good_crawler": {
    #             "risky_http_methods": 1,
    #             "robots_violations": 0,
    #             "uneven_request_timing": 0,
    #             "different_user_agents": 0,
    #             "attack_url": 0
    #         },
    #         "bad_crawler": {
    #             "risky_http_methods": 2,
    #             "robots_violations": 7,
    #             "uneven_request_timing": 0,
    #             "different_user_agents": 5,
    #             "attack_url": 5
    #         },
    #         "regular_user": {
    #             "risky_http_methods": 0,
    #             "robots_violations": 0,
    #             "uneven_request_timing": 8,
    #             "different_user_agents": 3,
    #             "attack_url": 0
    #         }
    #     }

    #     accesses = self.db.get_access_logs(ip_filter = ip, limit=1000)
    #     total_accesses_count = len(accesses)
    #     if total_accesses_count <= 0:
    #         return

    #     # Set category as "unknown" for the first 5 requests
    #     if total_accesses_count < 3:
    #         category = "unknown"
    #         analyzed_metrics = {}
    #         category_scores = {"attacker": 0, "good_crawler": 0, "bad_crawler": 0, "regular_user": 0, "unknown": 0}
    #         last_analysis = datetime.now(tz=ZoneInfo('UTC'))
    #         self._db_manager.update_ip_stats_analysis(ip, analyzed_metrics, category, category_scores, last_analysis)
    #         return 0

    #     #--------------------- HTTP Methods ---------------------

    #     get_accesses_count = len([item for item in accesses if item["method"] == "GET"])
    #     post_accesses_count = len([item for item in accesses if item["method"] == "POST"])
    #     put_accesses_count = len([item for item in accesses if item["method"] == "PUT"])
    #     delete_accesses_count = len([item for item in accesses if item["method"] == "DELETE"])
    #     head_accesses_count = len([item for item in accesses if item["method"] == "HEAD"])
    #     options_accesses_count = len([item for item in accesses if item["method"] == "OPTIONS"])
    #     patch_accesses_count = len([item for item in accesses if item["method"] == "PATCH"])

    #     if total_accesses_count > http_risky_methods_threshold:
    #         http_method_attacker_score = (post_accesses_count + put_accesses_count + delete_accesses_count + options_accesses_count + patch_accesses_count) / total_accesses_count
    #     else:
    #         http_method_attacker_score = 0

    #     #print(f"HTTP Method attacker score: {http_method_attacker_score}")
    #     if http_method_attacker_score >= http_risky_methods_threshold:
    #         score["attacker"]["risky_http_methods"] = True
    #         score["good_crawler"]["risky_http_methods"] = False
    #         score["bad_crawler"]["risky_http_methods"] = True
    #         score["regular_user"]["risky_http_methods"] = False
    #     else:
    #         score["attacker"]["risky_http_methods"] = False
    #         score["good_crawler"]["risky_http_methods"] = True
    #         score["bad_crawler"]["risky_http_methods"] = False
    #         score["regular_user"]["risky_http_methods"] = False

    #     #--------------------- Robots Violations ---------------------
    #     #respect robots.txt and login/config pages access frequency
    #     robots_disallows = []
    #     robots_path = Path(__file__).parent / "templates" / "html" / "robots.txt"
    #     with open(robots_path, "r") as f:
    #         for line in f:
    #             line = line.strip()
    #             if not line:
    #                 continue
    #             parts = line.split(":")

    #             if parts[0] == "Disallow":
    #                 parts[1] = parts[1].rstrip("/")
    #                 #print(f"DISALLOW {parts[1]}")
    #                 robots_disallows.append(parts[1].strip())

    #     #if 0 100% sure is good crawler, if >10% of robots violated is bad crawler or attacker
    #     violated_robots_count = len([item for item in accesses if any(item["path"].rstrip("/").startswith(disallow) for disallow in robots_disallows)])
    #     #print(f"Violated robots count: {violated_robots_count}")
    #     if total_accesses_count > 0:
    #         violated_robots_ratio = violated_robots_count / total_accesses_count
    #     else:
    #         violated_robots_ratio = 0

    #     if violated_robots_ratio >= violated_robots_threshold:
    #         score["attacker"]["robots_violations"] = True
    #         score["good_crawler"]["robots_violations"] = False
    #         score["bad_crawler"]["robots_violations"] = True
    #         score["regular_user"]["robots_violations"] = False
    #     else:
    #         score["attacker"]["robots_violations"] = False
    #         score["good_crawler"]["robots_violations"] = False
    #         score["bad_crawler"]["robots_violations"] = False
    #         score["regular_user"]["robots_violations"] = False

    #     #--------------------- Requests Timing ---------------------
    #     #Request rate and timing: steady, throttled, polite vs attackers' bursty, aggressive, or oddly rhythmic behavior
    #     timestamps = [datetime.fromisoformat(item["timestamp"]) for item in accesses]
    #     now_utc = datetime.now(tz=ZoneInfo('UTC'))
    #     timestamps = [ts for ts in timestamps if now_utc - ts <= timedelta(seconds=uneven_request_timing_time_window_seconds)]
    #     timestamps = sorted(timestamps, reverse=True)

    #     time_diffs = []
    #     for i in range(0, len(timestamps)-1):
    #         diff = (timestamps[i] - timestamps[i+1]).total_seconds()
    #         time_diffs.append(diff)

    #     mean = 0
    #     variance = 0
    #     std = 0
    #     cv = 0
    #     if time_diffs:
    #         mean = sum(time_diffs) / len(time_diffs)
    #         variance = sum((x - mean) ** 2 for x in time_diffs) / len(time_diffs)
    #         std = variance ** 0.5
    #         cv = std/mean
    #         app_logger.debug(f"Mean: {mean} - Variance {variance} - Standard Deviation {std} - Coefficient of Variation: {cv}")

    #     if cv >= uneven_request_timing_threshold:
    #         score["attacker"]["uneven_request_timing"] = True
    #         score["good_crawler"]["uneven_request_timing"] = False
    #         score["bad_crawler"]["uneven_request_timing"] = False
    #         score["regular_user"]["uneven_request_timing"] = True
    #     else:
    #         score["attacker"]["uneven_request_timing"] = False
    #         score["good_crawler"]["uneven_request_timing"] = False
    #         score["bad_crawler"]["uneven_request_timing"] = False
    #         score["regular_user"]["uneven_request_timing"] = False

    #     #--------------------- Different User Agents ---------------------
    #     #Header Quality and Consistency: Crawlers tend to use complete and consistent headers, attackers might miss, fake, or change headers
    #     user_agents_used = [item["user_agent"] for item in accesses]
    #     user_agents_used = list(dict.fromkeys(user_agents_used))
    #     #print(f"User agents used: {user_agents_used}")

    #     if len(user_agents_used) >= user_agents_used_threshold:
    #         score["attacker"]["different_user_agents"] = True
    #         score["good_crawler"]["different_user_agents"] = False
    #         score["bad_crawler"]["different_user_agentss"] = True
    #         score["regular_user"]["different_user_agents"] = False
    #     else:
    #         score["attacker"]["different_user_agents"] = False
    #         score["good_crawler"]["different_user_agents"] = False
    #         score["bad_crawler"]["different_user_agents"] = False
    #         score["regular_user"]["different_user_agents"] = False

    #     #--------------------- Attack URLs ---------------------

    #     attack_urls_found_list = []

    #     wl = get_wordlists()
    #     if wl.attack_patterns:
    #         queried_paths = [item["path"] for item in accesses]

    #         for queried_path in queried_paths:
    #             # URL decode the path to catch encoded attacks
    #             try:
    #                 decoded_path = urllib.parse.unquote(queried_path)
    #                 # Double decode to catch double-encoded attacks
    #                 decoded_path_twice = urllib.parse.unquote(decoded_path)
    #             except Exception:
    #                 decoded_path = queried_path
    #                 decoded_path_twice = queried_path

    #             for name, pattern in wl.attack_patterns.items():
    #                 # Check original, decoded, and double-decoded paths
    #                 if (re.search(pattern, queried_path, re.IGNORECASE) or
    #                     re.search(pattern, decoded_path, re.IGNORECASE) or
    #                     re.search(pattern, decoded_path_twice, re.IGNORECASE)):
    #                     attack_urls_found_list.append(f"{name}: {pattern}")

    #         #remove duplicates
    #         attack_urls_found_list = set(attack_urls_found_list)
    #         attack_urls_found_list = list(attack_urls_found_list)

    #         if len(attack_urls_found_list) > attack_urls_threshold:
    #             score["attacker"]["attack_url"] = True
    #             score["good_crawler"]["attack_url"] = False
    #             score["bad_crawler"]["attack_url"] = False
    #             score["regular_user"]["attack_url"] = False
    #         else:
    #             score["attacker"]["attack_url"] = False
    #             score["good_crawler"]["attack_url"] = False
    #             score["bad_crawler"]["attack_url"] = False
    #             score["regular_user"]["attack_url"] = False

    #     #--------------------- Calculate score ---------------------

    #     attacker_score = good_crawler_score = bad_crawler_score = regular_user_score = 0

    #     attacker_score = score["attacker"]["risky_http_methods"] * weights["attacker"]["risky_http_methods"]
    #     attacker_score = attacker_score + score["attacker"]["robots_violations"] * weights["attacker"]["robots_violations"]
    #     attacker_score = attacker_score + score["attacker"]["uneven_request_timing"] * weights["attacker"]["uneven_request_timing"]
    #     attacker_score = attacker_score + score["attacker"]["different_user_agents"] * weights["attacker"]["different_user_agents"]
    #     attacker_score = attacker_score + score["attacker"]["attack_url"] * weights["attacker"]["attack_url"]

    #     good_crawler_score = score["good_crawler"]["risky_http_methods"] * weights["good_crawler"]["risky_http_methods"]
    #     good_crawler_score = good_crawler_score + score["good_crawler"]["robots_violations"] * weights["good_crawler"]["robots_violations"]
    #     good_crawler_score = good_crawler_score + score["good_crawler"]["uneven_request_timing"] * weights["good_crawler"]["uneven_request_timing"]
    #     good_crawler_score = good_crawler_score + score["good_crawler"]["different_user_agents"] * weights["good_crawler"]["different_user_agents"]
    #     good_crawler_score = good_crawler_score + score["good_crawler"]["attack_url"] * weights["good_crawler"]["attack_url"]

    #     bad_crawler_score = score["bad_crawler"]["risky_http_methods"] * weights["bad_crawler"]["risky_http_methods"]
    #     bad_crawler_score = bad_crawler_score + score["bad_crawler"]["robots_violations"] * weights["bad_crawler"]["robots_violations"]
    #     bad_crawler_score = bad_crawler_score + score["bad_crawler"]["uneven_request_timing"] * weights["bad_crawler"]["uneven_request_timing"]
    #     bad_crawler_score = bad_crawler_score + score["bad_crawler"]["different_user_agents"] * weights["bad_crawler"]["different_user_agents"]
    #     bad_crawler_score = bad_crawler_score + score["bad_crawler"]["attack_url"] * weights["bad_crawler"]["attack_url"]

    #     regular_user_score = score["regular_user"]["risky_http_methods"] * weights["regular_user"]["risky_http_methods"]
    #     regular_user_score = regular_user_score + score["regular_user"]["robots_violations"] * weights["regular_user"]["robots_violations"]
    #     regular_user_score = regular_user_score + score["regular_user"]["uneven_request_timing"] * weights["regular_user"]["uneven_request_timing"]
    #     regular_user_score = regular_user_score + score["regular_user"]["different_user_agents"] * weights["regular_user"]["different_user_agents"]
    #     regular_user_score = regular_user_score + score["regular_user"]["attack_url"] * weights["regular_user"]["attack_url"]

    #     score_details = f"""
    #     Attacker score: {attacker_score}
    #     Good Crawler score: {good_crawler_score}
    #     Bad Crawler score: {bad_crawler_score}
    #     Regular User score: {regular_user_score}
    #     """
    #     app_logger.debug(score_details)

    #     analyzed_metrics = {"risky_http_methods": http_method_attacker_score, "robots_violations": violated_robots_ratio, "uneven_request_timing": mean, "different_user_agents": user_agents_used, "attack_url": attack_urls_found_list}
    #     category_scores = {"attacker": attacker_score, "good_crawler": good_crawler_score, "bad_crawler": bad_crawler_score, "regular_user": regular_user_score}
    #     category = max(category_scores, key=category_scores.get)
    #     last_analysis = datetime.now(tz=ZoneInfo('UTC'))

    #     self._db_manager.update_ip_stats_analysis(ip, analyzed_metrics, category, category_scores, last_analysis)

    #     return 0

    # def update_ip_rep_infos(self, ip: str) -> list[str]:
    #     api_url = "https://iprep.lcrawl.com/api/iprep/"
    #     params = {
    #         "cidr": ip
    #     }
    #     headers = {
    #         "Content-Type": "application/json"
    #     }

    #     response = requests.get(api_url, headers=headers, params=params)
    #     payload = response.json()

    #     if payload["results"]:
    #         data = payload["results"][0]

    #         country_iso_code = data["geoip_data"]["country_iso_code"]
    #         asn = data["geoip_data"]["asn_autonomous_system_number"]
    #         asn_org = data["geoip_data"]["asn_autonomous_system_organization"]
    #         list_on = data["list_on"]

    #         sanitized_country_iso_code = sanitize_for_storage(country_iso_code, 3)
    #         sanitized_asn = sanitize_for_storage(asn, 100)
    #         sanitized_asn_org = sanitize_for_storage(asn_org, 100)
    #         sanitized_list_on = sanitize_dict(list_on, 100000)

    #         self._db_manager.update_ip_rep_infos(ip, sanitized_country_iso_code, sanitized_asn, sanitized_asn_org, sanitized_list_on)

    #     return
