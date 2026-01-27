#!/usr/bin/env python3

"""
Test script to insert fake external IPs into the database for testing the dashboard.
This generates realistic-looking test data including:
- Access logs with various suspicious activities
- Credential attempts
- Attack detections (SQL injection, XSS, etc.)
- Category behavior changes for timeline demonstration
- Real good crawler IPs (Googlebot, Bingbot, etc.) with API-fetched geolocation

Usage:
    python test_insert_fake_ips.py [num_ips] [logs_per_ip] [credentials_per_ip] [--no-cleanup]

Examples:
    python test_insert_fake_ips.py              # Generate 20 IPs with defaults, cleanup DB first
    python test_insert_fake_ips.py 30           # Generate 30 IPs with defaults
    python test_insert_fake_ips.py 30 20 5      # Generate 30 IPs, 20 logs each, 5 credentials each
    python test_insert_fake_ips.py --no-cleanup # Generate data without cleaning DB first
"""

import random
import time
import sys
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from pathlib import Path
import requests

# Add parent src directory to path so we can import database and logger
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from database import get_database
from logger import get_app_logger

# ----------------------
# TEST DATA GENERATORS
# ----------------------

# Fake IPs with geolocation data (country_code, city, ASN org)
# These will appear on the map based on their country_code
FAKE_IPS_WITH_GEO = [
    # United States
    ("45.142.120.10", "US", "New York", "AS14061 DigitalOcean"),
    ("107.189.10.143", "US", "Los Angeles", "AS20473 Vultr"),
    ("162.243.175.23", "US", "San Francisco", "AS14061 DigitalOcean"),
    ("198.51.100.89", "US", "Chicago", "AS16509 Amazon"),

    # Europe
    ("185.220.101.45", "DE", "Berlin", "AS24940 Hetzner"),
    ("195.154.133.20", "FR", "Paris", "AS12876 Scaleway"),
    ("178.128.83.165", "GB", "London", "AS14061 DigitalOcean"),
    ("87.251.67.90", "NL", "Amsterdam", "AS49453 GlobalConnect"),
    ("91.203.5.165", "RU", "Moscow", "AS51115 HLL LLC"),
    ("46.105.57.169", "FR", "Roubaix", "AS16276 OVH"),
    ("217.182.143.207", "RU", "Saint Petersburg", "AS51570 JSC ER-Telecom"),
    ("188.166.123.45", "GB", "Manchester", "AS14061 DigitalOcean"),

    # Asia
    ("103.253.145.36", "CN", "Beijing", "AS4134 Chinanet"),
    ("42.112.28.216", "CN", "Shanghai", "AS4134 Chinanet"),
    ("118.163.74.160", "JP", "Tokyo", "AS2516 KDDI"),
    ("43.229.53.35", "SG", "Singapore", "AS23969 TOT"),
    ("115.78.208.140", "IN", "Mumbai", "AS9829 BSNL"),
    ("14.139.56.18", "IN", "Bangalore", "AS4755 TATA"),
    ("61.19.25.207", "TW", "Taipei", "AS3462 HiNet"),
    ("121.126.219.198", "KR", "Seoul", "AS4766 Korea Telecom"),
    ("202.134.4.212", "ID", "Jakarta", "AS7597 TELKOMNET"),
    ("171.244.140.134", "VN", "Hanoi", "AS7552 Viettel"),

    # South America
    ("177.87.169.20", "BR", "São Paulo", "AS28573 Claro"),
    ("200.21.19.58", "BR", "Rio de Janeiro", "AS7738 Telemar"),
    ("181.13.140.98", "AR", "Buenos Aires", "AS7303 Telecom Argentina"),
    ("190.150.24.34", "CO", "Bogotá", "AS3816 Colombia Telecomunicaciones"),

    # Middle East & Africa
    ("41.223.53.141", "EG", "Cairo", "AS8452 TE-Data"),
    ("196.207.35.152", "ZA", "Johannesburg", "AS37271 Workonline"),
    ("5.188.62.214", "TR", "Istanbul", "AS51115 HLL LLC"),
    ("37.48.93.125", "AE", "Dubai", "AS5384 Emirates Telecom"),
    ("102.66.137.29", "NG", "Lagos", "AS29465 MTN Nigeria"),

    # Australia & Oceania
    ("103.28.248.110", "AU", "Sydney", "AS4739 Internode"),
    ("202.168.45.33", "AU", "Melbourne", "AS1221 Telstra"),

    # Additional European IPs
    ("94.102.49.190", "PL", "Warsaw", "AS12912 T-Mobile"),
    ("213.32.93.140", "ES", "Madrid", "AS3352 Telefónica"),
    ("79.137.79.167", "IT", "Rome", "AS3269 Telecom Italia"),
    ("37.9.169.146", "SE", "Stockholm", "AS3301 Telia"),
    ("188.92.80.123", "RO", "Bucharest", "AS8708 RCS & RDS"),
    ("80.240.25.198", "CZ", "Prague", "AS6830 UPC"),
]

# Extract just IPs for backward compatibility
FAKE_IPS = [ip_data[0] for ip_data in FAKE_IPS_WITH_GEO]

# Create geo data dictionary
FAKE_GEO_DATA = {
    ip_data[0]: (ip_data[1], ip_data[2], ip_data[3])
    for ip_data in FAKE_IPS_WITH_GEO
}

# Real good crawler IPs (Googlebot, Bingbot, etc.) - geolocation will be fetched from API
GOOD_CRAWLER_IPS = [
    "66.249.66.1",      # Googlebot
    "66.249.79.23",     # Googlebot
    "40.77.167.52",     # Bingbot
    "157.55.39.145",    # Bingbot
    "17.58.98.100",     # Applebot
    "199.59.150.39",    # Twitterbot
    "54.236.1.15",      # Amazon Bot
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
    "attacker",
    "bad_crawler",
    "good_crawler",
    "regular_user",
    "unknown",
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


def cleanup_database(db_manager, app_logger):
    """
    Clean up all existing test data from the database.

    Args:
        db_manager: Database manager instance
        app_logger: Logger instance
    """
    from models import AccessLog, CredentialAttempt, AttackDetection, IpStats, CategoryHistory

    app_logger.info("=" * 60)
    app_logger.info("Cleaning up existing database data")
    app_logger.info("=" * 60)

    session = db_manager.session
    try:
        # Delete all records from each table
        deleted_attack_detections = session.query(AttackDetection).delete()
        deleted_access_logs = session.query(AccessLog).delete()
        deleted_credentials = session.query(CredentialAttempt).delete()
        deleted_category_history = session.query(CategoryHistory).delete()
        deleted_ip_stats = session.query(IpStats).delete()

        session.commit()

        app_logger.info(f"Deleted {deleted_access_logs} access logs")
        app_logger.info(f"Deleted {deleted_attack_detections} attack detections")
        app_logger.info(f"Deleted {deleted_credentials} credential attempts")
        app_logger.info(f"Deleted {deleted_category_history} category history records")
        app_logger.info(f"Deleted {deleted_ip_stats} IP statistics")
        app_logger.info("✓ Database cleanup complete")
    except Exception as e:
        session.rollback()
        app_logger.error(f"Error during database cleanup: {e}")
        raise
    finally:
        db_manager.close_session()


def fetch_geolocation_from_api(ip: str, app_logger) -> tuple:
    """
    Fetch geolocation data from the IP reputation API.

    Args:
        ip: IP address to lookup
        app_logger: Logger instance

    Returns:
        Tuple of (country_code, city, asn, asn_org) or None if failed
    """
    try:
        api_url = "https://iprep.lcrawl.com/api/iprep/"
        params = {"cidr": ip}
        headers = {"Content-Type": "application/json"}
        response = requests.get(api_url, headers=headers, params=params, timeout=10)

        if response.status_code == 200:
            payload = response.json()
            if payload.get("results"):
                data = payload["results"][0]
                geoip_data = data.get("geoip_data", {})

                country_code = geoip_data.get("country_iso_code", "Unknown")
                city = geoip_data.get("city_name", "Unknown")
                asn = geoip_data.get("asn_autonomous_system_number")
                asn_org = geoip_data.get("asn_autonomous_system_organization", "Unknown")

                return (country_code, city, asn, asn_org)
    except requests.RequestException as e:
        app_logger.warning(f"Failed to fetch geolocation for {ip}: {e}")
    except Exception as e:
        app_logger.error(f"Error processing geolocation for {ip}: {e}")

    return None


def generate_fake_data(num_ips: int = 20, logs_per_ip: int = 15, credentials_per_ip: int = 3, include_good_crawlers: bool = True, cleanup: bool = True):
    """
    Generate and insert fake test data into the database.

    Args:
        num_ips: Number of unique fake IPs to generate (default: 20)
        logs_per_ip: Number of access logs per IP (default: 15)
        credentials_per_ip: Number of credential attempts per IP (default: 3)
        include_good_crawlers: Whether to add real good crawler IPs with API-fetched geolocation (default: True)
        cleanup: Whether to clean up existing database data before generating new data (default: True)
    """
    db_manager = get_database()
    app_logger = get_app_logger()

    # Ensure database is initialized
    if not db_manager._initialized:
        db_manager.initialize()

    # Clean up existing data if requested
    if cleanup:
        cleanup_database(db_manager, app_logger)
        print()  # Add blank line for readability

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

        # Add geolocation data if available for this IP
        if ip in FAKE_GEO_DATA:
            country_code, city, asn_org = FAKE_GEO_DATA[ip]
            # Extract ASN number from ASN string (e.g., "AS12345 Name" -> 12345)
            asn_number = None
            if asn_org and asn_org.startswith("AS"):
                try:
                    asn_number = int(asn_org.split()[0][2:])  # Remove "AS" prefix and get number
                except (ValueError, IndexError):
                    asn_number = 12345  # Fallback

            # Update IP reputation info including geolocation and city
            db_manager.update_ip_rep_infos(
                ip=ip,
                country_code=country_code,
                asn=asn_number or 12345,
                asn_org=asn_org,
                list_on={},
                city=city  # Now passing city to the function
            )
            app_logger.info(f"  📍 Added geolocation: {city}, {country_code} ({asn_org})")

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

    # Add good crawler IPs with real geolocation from API
    total_good_crawlers = 0
    if include_good_crawlers:
        app_logger.info("\n" + "=" * 60)
        app_logger.info("Adding Good Crawler IPs with API-fetched geolocation")
        app_logger.info("=" * 60)

        for crawler_ip in GOOD_CRAWLER_IPS:
            app_logger.info(f"\nProcessing Good Crawler: {crawler_ip}")

            # Fetch real geolocation from API
            geo_data = fetch_geolocation_from_api(crawler_ip, app_logger)

            # Don't generate access logs for good crawlers to prevent re-categorization
            # We'll just create the IP stats entry with the category set
            app_logger.info(f"  ✓ Adding as good crawler (no logs to prevent re-categorization)")

            # First, we need to create the IP in the database via persist_access
            # (but we'll only create one minimal log entry)
            db_manager.persist_access(
                ip=crawler_ip,
                path="/robots.txt",  # Minimal, normal crawler behavior
                user_agent="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                method="GET",
                is_suspicious=False,
                is_honeypot_trigger=False,
                attack_types=None,
            )

            # Add geolocation if API fetch was successful
            if geo_data:
                country_code, city, asn, asn_org = geo_data
                db_manager.update_ip_rep_infos(
                    ip=crawler_ip,
                    country_code=country_code,
                    asn=asn if asn else 12345,
                    asn_org=asn_org,
                    list_on={},
                    city=city
                )
                app_logger.info(f"  📍 API-fetched geolocation: {city}, {country_code} ({asn_org})")
            else:
                app_logger.warning(f"  ⚠ Could not fetch geolocation for {crawler_ip}")

            # Set category to good_crawler - this sets manual_category=True to prevent re-analysis
            db_manager.update_ip_stats_analysis(
                ip=crawler_ip,
                analyzed_metrics={
                    "request_frequency": 0.1,  # Very low frequency
                    "suspicious_patterns": 0,
                    "credential_attempts": 0,
                    "attack_diversity": 0.0,
                },
                category="good_crawler",
                category_scores={
                    "attacker": 0,
                    "good_crawler": 100,
                    "bad_crawler": 0,
                    "regular_user": 0,
                    "unknown": 0,
                },
                last_analysis=datetime.now(tz=ZoneInfo('UTC'))
            )
            total_good_crawlers += 1
            time.sleep(0.5)  # Small delay between API calls

    # Print summary
    app_logger.info("\n" + "=" * 60)
    app_logger.info("Test Data Generation Complete!")
    app_logger.info("=" * 60)
    app_logger.info(f"Total IPs created: {len(selected_ips) + total_good_crawlers}")
    app_logger.info(f"  - Attackers/Mixed: {len(selected_ips)}")
    app_logger.info(f"  - Good Crawlers: {total_good_crawlers}")
    app_logger.info(f"Total access logs: {total_logs}")
    app_logger.info(f"Total attack detections: {total_attacks}")
    app_logger.info(f"Total credential attempts: {total_credentials}")
    app_logger.info(f"Total category changes: {total_category_changes}")
    app_logger.info("=" * 60)
    app_logger.info("\nYou can now view the dashboard with this test data.")
    app_logger.info("The 'Behavior Timeline' will show category transitions for each IP.")
    app_logger.info("The map will show good crawlers with real geolocation from API.")
    app_logger.info("Run: python server.py")
    app_logger.info("=" * 60)


if __name__ == "__main__":
    import sys

    # Allow command-line arguments for customization
    num_ips = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    logs_per_ip = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    credentials_per_ip = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    # Add --no-cleanup flag to skip database cleanup
    cleanup = "--no-cleanup" not in sys.argv

    generate_fake_data(num_ips, logs_per_ip, credentials_per_ip, include_good_crawlers=True, cleanup=cleanup)
