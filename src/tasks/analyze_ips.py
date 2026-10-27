from collections import Counter
from datetime import datetime, timedelta

import metrics
from config import get_config
from database import get_database
from logger import get_app_logger

# ----------------------
# TASK CONFIG
# ----------------------

TASK_CONFIG = {
    "name": "analyze-ips",
    "cron": "*/1 * * * *",
    "enabled": True,
    # runs every minute anyway; a boot run only duplicates it.
    "run_when_loaded": False,
    # One pod per minute analyses the batch; the others would redo the same rows.
    "single_pod": True,
}

# Upper bound on IPs analysed per run (config `tasks.analyze_ips_batch`); the
# remainder is picked up next minute. The default is sized from the real
# workload: the vast majority of flagged IPs have under 100 rows to read, so
# 2000 fits comfortably inside the one-minute window.


def robots_disallows() -> list[str]:
    """Disallowed paths from the bundled robots.txt page."""
    from detection import get_response_catalog

    return list(get_response_catalog().robots_disallows)


def main():
    config = get_config()
    max_ips = config.tasks_analyze_ips_batch
    db_manager = get_database()
    app_logger = get_app_logger()

    metrics.refresh_ai(db_manager)
    metrics.refresh_system(db_manager)

    http_risky_methods_threshold = config.http_risky_methods_threshold
    violated_robots_threshold = config.violated_robots_threshold
    uneven_request_timing_threshold = config.uneven_request_timing_threshold
    user_agents_used_threshold = config.user_agents_used_threshold
    attack_urls_threshold = config.attack_urls_threshold
    uneven_request_timing_time_window_seconds = (
        config.uneven_request_timing_time_window_seconds
    )
    app_logger.debug(f"http_risky_methods_threshold: {http_risky_methods_threshold}")
    score = {}
    score["attacker"] = {
        "risky_http_methods": False,
        "robots_violations": False,
        "uneven_request_timing": False,
        "different_user_agents": False,
        "attack_url": False,
    }
    score["good_crawler"] = {
        "risky_http_methods": False,
        "robots_violations": False,
        "uneven_request_timing": False,
        "different_user_agents": False,
        "attack_url": False,
    }
    score["bad_crawler"] = {
        "risky_http_methods": False,
        "robots_violations": False,
        "uneven_request_timing": False,
        "different_user_agents": False,
        "attack_url": False,
    }
    score["regular_user"] = {
        "risky_http_methods": False,
        "robots_violations": False,
        "uneven_request_timing": False,
        "different_user_agents": False,
        "attack_url": False,
    }

    weights = get_config().scoring_weights
    disallowed_paths = robots_disallows()

    # IPs flagged for reevaluation, plus any never analysed at all — the
    # ordering and the cap are both applied in SQL, see the repo method.
    ips_to_analyze = db_manager.ip_stats.get_ips_needing_reevaluation(limit=max_ips)

    if not ips_to_analyze:
        app_logger.debug(
            "[Background Task] analyze-ips: No IPs need reevaluation, skipping"
        )
        return

    if len(ips_to_analyze) == max_ips:
        app_logger.info(
            f"[Background Task] analyze-ips: batch full at {max_ips}, "
            "more IPs pending for the next run"
        )

    for ip in ips_to_analyze:
        # Get full history for this IP to perform accurate analysis
        ip_accesses = db_manager.access_logs.get_list(
            limit=10000, ip_filter=ip, since_minutes=1440 * 30
        )  # look back up to 30 days of history for better accuracy
        # A crunched row stands for hit_count requests; weighting by it keeps
        # crunching from moving any ratio (docs/algorithms.md).
        hits = [item.get("hit_count") or 1 for item in ip_accesses]
        total_accesses_count = sum(hits)
        if total_accesses_count <= 0:
            # No history left in the window (logs aged out or were purged).
            # Clear the flag anyway, or this IP is re-read on every run forever.
            db_manager.ip_stats.mark_analysed(ip, datetime.now())
            continue

        # --------------------- HTTP Methods ---------------------
        method_counts = Counter()
        for item, n in zip(ip_accesses, hits, strict=True):
            method_counts[item["method"]] += n
        if total_accesses_count > http_risky_methods_threshold:
            risky_count = sum(
                method_counts.get(m, 0)
                for m in ("POST", "PUT", "DELETE", "OPTIONS", "PATCH")
            )
            http_method_attacker_score = risky_count / total_accesses_count
        else:
            http_method_attacker_score = 0
        # print(f"HTTP Method attacker score: {http_method_attacker_score}")
        if http_method_attacker_score >= http_risky_methods_threshold:
            score["attacker"]["risky_http_methods"] = True
            score["good_crawler"]["risky_http_methods"] = False
            score["bad_crawler"]["risky_http_methods"] = True
            score["regular_user"]["risky_http_methods"] = False
        else:
            score["attacker"]["risky_http_methods"] = False
            score["good_crawler"]["risky_http_methods"] = True
            score["bad_crawler"]["risky_http_methods"] = False
            score["regular_user"]["risky_http_methods"] = False
        # --------------------- Robots Violations ---------------------
        violated_robots_count = sum(
            n
            for item, n in zip(ip_accesses, hits, strict=True)
            if any(
                item["path"].rstrip("/").startswith(disallow)
                for disallow in disallowed_paths
            )
        )
        # print(f"Violated robots count: {violated_robots_count}")
        if total_accesses_count > 0:
            violated_robots_ratio = violated_robots_count / total_accesses_count
        else:
            violated_robots_ratio = 0
        if violated_robots_ratio >= violated_robots_threshold:
            score["attacker"]["robots_violations"] = True
            score["good_crawler"]["robots_violations"] = False
            score["bad_crawler"]["robots_violations"] = True
            score["regular_user"]["robots_violations"] = False
        else:
            score["attacker"]["robots_violations"] = False
            score["good_crawler"]["robots_violations"] = False
            score["bad_crawler"]["robots_violations"] = False
            score["regular_user"]["robots_violations"] = False

        # --------------------- Requests Timing ---------------------
        # Request rate and timing: steady, throttled, polite vs attackers' bursty, aggressive, or oddly rhythmic behavior
        timestamps = [datetime.fromisoformat(item["timestamp"]) for item in ip_accesses]
        now_utc = datetime.now()
        timestamps = [
            ts
            for ts in timestamps
            if now_utc - ts
            <= timedelta(seconds=uneven_request_timing_time_window_seconds)
        ]
        timestamps = sorted(timestamps, reverse=True)
        time_diffs = []
        for i in range(0, len(timestamps) - 1):
            diff = (timestamps[i] - timestamps[i + 1]).total_seconds()
            time_diffs.append(diff)

        mean = 0
        variance = 0
        std = 0
        cv = 0
        if time_diffs:
            mean = sum(time_diffs) / len(time_diffs)
            variance = sum((x - mean) ** 2 for x in time_diffs) / len(time_diffs)
            std = variance**0.5
            cv = std / mean
            app_logger.debug(
                f"Mean: {mean} - Variance {variance} - Standard Deviation {std} - Coefficient of Variation: {cv}"
            )
        if cv >= uneven_request_timing_threshold:
            score["attacker"]["uneven_request_timing"] = True
            score["good_crawler"]["uneven_request_timing"] = False
            score["bad_crawler"]["uneven_request_timing"] = False
            score["regular_user"]["uneven_request_timing"] = True
        else:
            score["attacker"]["uneven_request_timing"] = False
            score["good_crawler"]["uneven_request_timing"] = False
            score["bad_crawler"]["uneven_request_timing"] = False
            score["regular_user"]["uneven_request_timing"] = False
        # --------------------- Different User Agents ---------------------
        # Header Quality and Consistency: Crawlers tend to use complete and consistent headers, attackers might miss, fake, or change headers
        user_agents_used = [item["user_agent"] for item in ip_accesses]
        user_agents_used = list(dict.fromkeys(user_agents_used))
        # print(f"User agents used: {user_agents_used}")
        if len(user_agents_used) >= user_agents_used_threshold:
            score["attacker"]["different_user_agents"] = True
            score["good_crawler"]["different_user_agents"] = False
            score["bad_crawler"]["different_user_agents"] = True
            score["regular_user"]["different_user_agents"] = False
        else:
            score["attacker"]["different_user_agents"] = False
            score["good_crawler"]["different_user_agents"] = False
            score["bad_crawler"]["different_user_agents"] = False
            score["regular_user"]["different_user_agents"] = False
        # --------------------- Attack URLs ---------------------
        # Distinct attack types stored when the requests arrived, from any field
        # (path, query, body, headers); only attack-class findings are stored.
        attack_urls_found_list = sorted(
            {
                attack_type
                for item in ip_accesses
                for attack_type in item.get("attack_types") or ()
            }
        )
        if len(attack_urls_found_list) >= attack_urls_threshold:
            score["attacker"]["attack_url"] = True
            score["good_crawler"]["attack_url"] = False
            score["bad_crawler"]["attack_url"] = False
            score["regular_user"]["attack_url"] = False
        else:
            score["attacker"]["attack_url"] = False
            score["good_crawler"]["attack_url"] = False
            score["bad_crawler"]["attack_url"] = False
            score["regular_user"]["attack_url"] = False
        # --------------------- Calculate score ---------------------
        attacker_score = good_crawler_score = bad_crawler_score = regular_user_score = 0
        attacker_score = (
            score["attacker"]["risky_http_methods"]
            * weights["attacker"]["risky_http_methods"]
        )
        attacker_score = (
            attacker_score
            + score["attacker"]["robots_violations"]
            * weights["attacker"]["robots_violations"]
        )
        attacker_score = (
            attacker_score
            + score["attacker"]["uneven_request_timing"]
            * weights["attacker"]["uneven_request_timing"]
        )
        attacker_score = (
            attacker_score
            + score["attacker"]["different_user_agents"]
            * weights["attacker"]["different_user_agents"]
        )
        attacker_score = (
            attacker_score
            + score["attacker"]["attack_url"] * weights["attacker"]["attack_url"]
        )
        good_crawler_score = (
            score["good_crawler"]["risky_http_methods"]
            * weights["good_crawler"]["risky_http_methods"]
        )
        good_crawler_score = (
            good_crawler_score
            + score["good_crawler"]["robots_violations"]
            * weights["good_crawler"]["robots_violations"]
        )
        good_crawler_score = (
            good_crawler_score
            + score["good_crawler"]["uneven_request_timing"]
            * weights["good_crawler"]["uneven_request_timing"]
        )
        good_crawler_score = (
            good_crawler_score
            + score["good_crawler"]["different_user_agents"]
            * weights["good_crawler"]["different_user_agents"]
        )
        good_crawler_score = (
            good_crawler_score
            + score["good_crawler"]["attack_url"]
            * weights["good_crawler"]["attack_url"]
        )
        bad_crawler_score = (
            score["bad_crawler"]["risky_http_methods"]
            * weights["bad_crawler"]["risky_http_methods"]
        )
        bad_crawler_score = (
            bad_crawler_score
            + score["bad_crawler"]["robots_violations"]
            * weights["bad_crawler"]["robots_violations"]
        )
        bad_crawler_score = (
            bad_crawler_score
            + score["bad_crawler"]["uneven_request_timing"]
            * weights["bad_crawler"]["uneven_request_timing"]
        )
        bad_crawler_score = (
            bad_crawler_score
            + score["bad_crawler"]["different_user_agents"]
            * weights["bad_crawler"]["different_user_agents"]
        )
        bad_crawler_score = (
            bad_crawler_score
            + score["bad_crawler"]["attack_url"] * weights["bad_crawler"]["attack_url"]
        )
        regular_user_score = (
            score["regular_user"]["risky_http_methods"]
            * weights["regular_user"]["risky_http_methods"]
        )
        regular_user_score = (
            regular_user_score
            + score["regular_user"]["robots_violations"]
            * weights["regular_user"]["robots_violations"]
        )
        regular_user_score = (
            regular_user_score
            + score["regular_user"]["uneven_request_timing"]
            * weights["regular_user"]["uneven_request_timing"]
        )
        regular_user_score = (
            regular_user_score
            + score["regular_user"]["different_user_agents"]
            * weights["regular_user"]["different_user_agents"]
        )
        regular_user_score = (
            regular_user_score
            + score["regular_user"]["attack_url"]
            * weights["regular_user"]["attack_url"]
        )
        score_details = f"""
        Attacker score: {attacker_score}
        Good Crawler score: {good_crawler_score}
        Bad Crawler score: {bad_crawler_score}
        Regular User score: {regular_user_score}
        """
        app_logger.debug(score_details)
        analyzed_metrics = {
            "risky_http_methods": http_method_attacker_score,
            "robots_violations": violated_robots_ratio,
            "uneven_request_timing": mean,
            "different_user_agents": user_agents_used,
            "attack_url": attack_urls_found_list,
        }
        category_scores = {
            "attacker": attacker_score,
            "good_crawler": good_crawler_score,
            "bad_crawler": bad_crawler_score,
            "regular_user": regular_user_score,
        }

        category = max(category_scores, key=category_scores.get)

        last_analysis = datetime.now()
        db_manager.ip_stats.update_ip_stats_analysis(
            ip, analyzed_metrics, category, category_scores, last_analysis
        )
    return


def on_skip() -> None:
    """Another pod owns this occurrence; still refresh this pod's gauges.

    krawl_generated_pages_today, krawl_ips_needing_reevaluation,
    krawl_unenriched_ips and krawl_auth_locked_ips are prometheus_client Gauges
    living in this process's memory, not in Redis. A pod that never sets them
    exports 0, and the dashboard's max() then reports whichever pod last held
    the lease -- a stale high-water mark instead of the current value.

    Four indexed COUNTs. Only the analysis loop above is worth deduplicating.
    """
    db_manager = get_database()
    metrics.refresh_ai(db_manager)
    metrics.refresh_system(db_manager)
