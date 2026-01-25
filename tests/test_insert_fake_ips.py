#!/usr/bin/env python3

"""
Test script to insert fake external IPs into the database for testing the dashboard.
This generates realistic-looking test data including access logs, credential attempts, and attack detections.
Also triggers category behavior changes to demonstrate the timeline feature.
"""

import random
import time
import sys
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from pathlib import Path

# Add parent src directory to path so we can import database and logger
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from database import get_database
from logger import get_app_logger

# ----------------------
# TEST DATA GENERATORS
# ----------------------

FAKE_IPS = [
    "203.0.113.45",      # Regular attacker IP
    "198.51.100.89",     # Credential harvester IP
    "192.0.2.120",       # Bot IP
    "205.32.180.65",     # Another attacker
    "210.45.67.89",      # Suspicious IP
    "175.23.45.67",      # International IP
    "182.91.102.45",     # Another suspicious IP
]

FAKE_PATHS = [
    "/admin",
    "/login",
    "/admin/login",
    "/api/users",
    "/wp-admin",
    "/.env",
    "/config.php",
    "/admin.php",
    "/shell.php",
    "/../../../etc/passwd",
    "/sqlmap",
    "/w00t.php",
    "/shell",
    "/joomla/administrator",
]

FAKE_USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Nmap Scripting Engine",
    "curl/7.68.0",
    "python-requests/2.28.1",
    "sqlmap/1.6.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "ZmEu",
    "nikto/2.1.6",
]

FAKE_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "123456"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "12345"),
]

ATTACK_TYPES = [
    "sql_injection",
    "xss_attempt",
    "path_traversal",
    "suspicious_pattern",
    "credential_submission",
]

CATEGORIES = [
    "ATTACKER",
    "BAD_CRAWLER",
    "GOOD_CRAWLER",
    "REGULAR_USER",
    "UNKNOWN",
]


def generate_category_scores():
    """Generate random category scores."""
    scores = {
        "attacker": random.randint(0, 100),
        "good_crawler": random.randint(0, 100),
        "bad_crawler": random.randint(0, 100),
        "regular_user": random.randint(0, 100),
        "unknown": random.randint(0, 100),
    }
    return scores


def generate_analyzed_metrics():
    """Generate random analyzed metrics."""
    return {
        "request_frequency": random.uniform(0.1, 100.0),
        "suspicious_patterns": random.randint(0, 20),
        "credential_attempts": random.randint(0, 10),
        "attack_diversity": random.uniform(0, 1.0),
    }


def generate_fake_data(num_ips: int = 45, logs_per_ip: int = 15, credentials_per_ip: int = 3):
    """
    Generate and insert fake test data into the database.

    Args:
        num_ips: Number of unique fake IPs to generate (default: 5)
        logs_per_ip: Number of access logs per IP (default: 15)
        credentials_per_ip: Number of credential attempts per IP (default: 3)
    """
    db_manager = get_database()
    app_logger = get_app_logger()

    # Ensure database is initialized
    if not db_manager._initialized:
        db_manager.initialize()

    app_logger.info("=" * 60)
    app_logger.info("Starting fake IP data generation for testing")
    app_logger.info("=" * 60)

    total_logs = 0
    total_credentials = 0
    total_attacks = 0
    total_category_changes = 0

    # Select random IPs from the pool
    selected_ips = random.sample(FAKE_IPS, min(num_ips, len(FAKE_IPS)))

    for ip in selected_ips:
        app_logger.info(f"\nGenerating data for IP: {ip}")

        # Generate access logs for this IP
        for _ in range(logs_per_ip):
            path = random.choice(FAKE_PATHS)
            user_agent = random.choice(FAKE_USER_AGENTS)
            is_suspicious = random.choice([True, False, False])  # 33% chance of suspicious
            is_honeypot = random.choice([True, False, False, False])  # 25% chance of honeypot trigger

            # Randomly decide if this log has attack detections
            attack_types = None
            if random.choice([True, False, False]):  # 33% chance
                num_attacks = random.randint(1, 3)
                attack_types = random.sample(ATTACK_TYPES, num_attacks)

            log_id = db_manager.persist_access(
                ip=ip,
                path=path,
                user_agent=user_agent,
                method=random.choice(["GET", "POST"]),
                is_suspicious=is_suspicious,
                is_honeypot_trigger=is_honeypot,
                attack_types=attack_types,
            )

            if log_id:
                total_logs += 1
                if attack_types:
                    total_attacks += len(attack_types)

        # Generate credential attempts for this IP
        for _ in range(credentials_per_ip):
            username, password = random.choice(FAKE_CREDENTIALS)
            path = random.choice(["/login", "/admin/login", "/api/auth"])

            cred_id = db_manager.persist_credential(
                ip=ip,
                path=path,
                username=username,
                password=password,
            )

            if cred_id:
                total_credentials += 1

        app_logger.info(f"  ✓ Generated {logs_per_ip} access logs")
        app_logger.info(f"  ✓ Generated {credentials_per_ip} credential attempts")

        # Trigger behavior/category changes to demonstrate timeline feature
        # First analysis
        initial_category = random.choice(CATEGORIES)
        app_logger.info(f"  ⟳ Analyzing behavior - Initial category: {initial_category}")
        
        db_manager.update_ip_stats_analysis(
            ip=ip,
            analyzed_metrics=generate_analyzed_metrics(),
            category=initial_category,
            category_scores=generate_category_scores(),
            last_analysis=datetime.now(tz=ZoneInfo('UTC'))
        )
        total_category_changes += 1

        # Small delay to ensure timestamps are different
        time.sleep(0.1)

        # Second analysis with potential category change (70% chance)
        if random.random() < 0.7:
            new_category = random.choice([c for c in CATEGORIES if c != initial_category])
            app_logger.info(f"  ⟳ Behavior change detected: {initial_category} → {new_category}")
            
            db_manager.update_ip_stats_analysis(
                ip=ip,
                analyzed_metrics=generate_analyzed_metrics(),
                category=new_category,
                category_scores=generate_category_scores(),
                last_analysis=datetime.now(tz=ZoneInfo('UTC'))
            )
            total_category_changes += 1

            # Optional third change (40% chance)
            if random.random() < 0.4:
                final_category = random.choice([c for c in CATEGORIES if c != new_category])
                app_logger.info(f"  ⟳ Another behavior change: {new_category} → {final_category}")
                
                time.sleep(0.1)
                db_manager.update_ip_stats_analysis(
                    ip=ip,
                    analyzed_metrics=generate_analyzed_metrics(),
                    category=final_category,
                    category_scores=generate_category_scores(),
                    last_analysis=datetime.now(tz=ZoneInfo('UTC'))
                )
                total_category_changes += 1

    # Print summary
    app_logger.info("\n" + "=" * 60)
    app_logger.info("Test Data Generation Complete!")
    app_logger.info("=" * 60)
    app_logger.info(f"Total IPs created: {len(selected_ips)}")
    app_logger.info(f"Total access logs: {total_logs}")
    app_logger.info(f"Total attack detections: {total_attacks}")
    app_logger.info(f"Total credential attempts: {total_credentials}")
    app_logger.info(f"Total category changes: {total_category_changes}")
    app_logger.info("=" * 60)
    app_logger.info("\nYou can now view the dashboard with this test data.")
    app_logger.info("The 'Behavior Timeline' will show category transitions for each IP.")
    app_logger.info("Run: python server.py")
    app_logger.info("=" * 60)


if __name__ == "__main__":
    import sys

    # Allow command-line arguments for customization
    num_ips = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    logs_per_ip = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    credentials_per_ip = int(sys.argv[3]) if len(sys.argv) > 3 else 3

    generate_fake_data(num_ips, logs_per_ip, credentials_per_ip)
