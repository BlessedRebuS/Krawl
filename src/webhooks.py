#!/usr/bin/env python3

"""
Webhook configuration and CloudFlare integration.
Stores webhook configs in data/webhooks.json.
"""

import json
import os
import threading

import requests

from logger import get_app_logger

_lock = threading.Lock()
_config_path = None


def _get_config_path() -> str:
    global _config_path
    if _config_path is None:
        _config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "data", "webhooks.json"
        )
    return _config_path


def _default_config() -> dict:
    return {
        "cloudflare": {
            "enabled": False,
            "account_id": "",
            "auth_token": "",
            "list_id": None,
            "list_name": "krawl_banlist",
            "list_description": "IPs banned by Krawl honeypot",
            "sync_interval_minutes": 30,
            "categories": ["attacker"],
            "last_sync": None,
            "last_sync_status": None,
            "last_sync_error": None,
        }
    }


def load_config() -> dict:
    path = _get_config_path()
    with _lock:
        if not os.path.exists(path):
            return _default_config()
        try:
            with open(path) as f:
                data = json.load(f)
            default = _default_config()
            for key, val in default.items():
                if key not in data:
                    data[key] = val
                elif isinstance(val, dict):
                    for k2, v2 in val.items():
                        if k2 not in data[key]:
                            data[key][k2] = v2
            return data
        except (json.JSONDecodeError, OSError) as e:
            get_app_logger().warning(f"[Webhooks] Failed to load config: {e}")
            return _default_config()


def save_config(data: dict) -> None:
    path = _get_config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _lock:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)


def get_cloudflare_config() -> dict:
    return load_config().get("cloudflare", {})


def save_cloudflare_config(cf_config: dict) -> None:
    data = load_config()
    data["cloudflare"] = cf_config
    save_config(data)


def _cf_headers(auth_token: str) -> dict:
    return {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json",
    }


def _cf_request(
    method: str, url: str, auth_token: str, json_body=None, timeout=30
) -> dict:
    """Make a CF API request with robust error handling."""
    try:
        resp = requests.request(
            method,
            url,
            headers=_cf_headers(auth_token),
            json=json_body,
            timeout=timeout,
        )
        get_app_logger().debug(f"[CF API] {method} {url} -> {resp.status_code}")
        # Try JSON parse, fall back to raw text on non-JSON responses
        try:
            data = resp.json()
        except (ValueError, requests.exceptions.JSONDecodeError):
            get_app_logger().warning(
                f"[CF API] Non-JSON response ({resp.status_code}): {resp.text[:500]}"
            )
            return {
                "success": False,
                "errors": [
                    {
                        "code": 0,
                        "message": f"Non-JSON response (HTTP {resp.status_code}): {resp.text[:200]}",
                    }
                ],
            }
        if not data.get("success"):
            errors = data.get("errors", [])
            get_app_logger().warning(f"[CF API] Error: {errors}")
        return data
    except requests.RequestException as e:
        get_app_logger().error(f"[CF API] Request failed: {e}")
        return {"success": False, "errors": [{"code": 0, "message": str(e)}]}


def cf_create_list(
    account_id: str, auth_token: str, name: str, description: str
) -> dict:
    """Create a new CloudFlare IP List via POST."""
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/rules/lists"
    return _cf_request(
        "POST",
        url,
        auth_token,
        json_body={
            "name": name,
            "kind": "ip",
            "description": description,
        },
    )


def cf_list_items(account_id: str, auth_token: str, list_id: str) -> dict:
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/rules/lists/{list_id}/items"
    return _cf_request("GET", url, auth_token)


def cf_replace_items(
    account_id: str, auth_token: str, list_id: str, ips: list[str]
) -> dict:
    """Replace all items in a CF list with the given IPs (full replace via PUT)."""
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/rules/lists/{list_id}/items"
    payload = [{"ip": ip} for ip in ips]
    get_app_logger().info(f"[CF Sync] PUT {len(ips)} items to list {list_id}")
    return _cf_request("PUT", url, auth_token, json_body=payload, timeout=60)


def cf_test_connection(account_id: str, auth_token: str) -> dict:
    """Test by listing all IP lists. Uses Lists:Read scope that sync actually needs."""
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/rules/lists"
    return _cf_request("GET", url, auth_token, timeout=15)


def cf_get_list(account_id: str, auth_token: str, list_id: str) -> dict:
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/rules/lists/{list_id}"
    return _cf_request("GET", url, auth_token, timeout=15)


def cf_get_zone(zone_id: str, auth_token: str) -> dict:
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}"
    return _cf_request("GET", url, auth_token, timeout=15)


def cf_get_custom_ruleset(zone_id: str, auth_token: str) -> dict:
    """Fetch the custom rules (http_request_firewall_custom) phase entrypoint for a zone."""
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint"
    return _cf_request("GET", url, auth_token, timeout=15)


def cf_ensure_custom_rule(
    zone_id: str,
    auth_token: str,
    list_name: str,
    action: str,
    description: str = "Krawl banlist",
) -> dict:
    """Create a WAF custom rule referencing the banlist if one doesn't already exist."""
    expr = f"ip.src in ${list_name}"
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint"
    ruleset = cf_get_custom_ruleset(zone_id, auth_token)
    if not ruleset.get("success"):
        errors = [e.get("message", str(e)) for e in ruleset.get("errors", [])]
        return {"created": False, "error": f"Failed to fetch custom ruleset: {errors}"}

    existing_rules = ruleset.get("result", {}).get("rules", [])
    for rule in existing_rules:
        if list_name in rule.get("expression", ""):
            get_app_logger().info(f"[CF Sync] WAF rule already exists for ${list_name}")
            return {"created": False, "exists": True}

    # PUT replaces the whole ruleset, so carry over existing rules (POST/DELETE
    # are not allowed for this auth scheme; entrypoint GET always succeeds).
    new_rule = {
        "description": description,
        "expression": expr,
        "action": action,
        "enabled": True,
    }
    result = _cf_request(
        "PUT",
        url,
        auth_token,
        json_body={"rules": existing_rules + [new_rule]},
        timeout=30,
    )
    if not result.get("success"):
        errors = [e.get("message", str(e)) for e in result.get("errors", [])]
        if any("not_found" in str(m) for m in errors):
            return {
                "created": False,
                "error": (
                    "Zone not found or not in this token's zone scope: "
                    "check the Zone ID and that the token's Zone Resources "
                    "include this zone (Zone > WAF > Edit permission required)"
                ),
            }
        return {"created": False, "error": f"Failed to create WAF rule: {errors}"}

    get_app_logger().info(f"[CF Sync] Created WAF rule: {expr} -> {action}")
    return {"created": True}


def sync_banlist_to_cloudflare(cf_config: dict) -> dict:
    """Sync the current banlist to CloudFlare. Returns status dict."""
    account_id = cf_config.get("account_id", "")
    auth_token = cf_config.get("auth_token", "")
    list_id = cf_config.get("list_id")
    categories = cf_config.get("categories", ["attacker"])

    if not account_id or not auth_token:
        return {"status": "error", "error": "Missing account_id or auth_token"}

    from config import get_config
    from ip_utils import is_valid_public_ip

    config = get_config()
    server_ip = config.get_server_ip()

    ip_set: set[str] = set()

    real_cats = [c for c in categories if c != "timed_out"]
    if real_cats:
        try:
            from database import get_database

            db = get_database()
            ip_set.update(db.ip_stats.get_ips_for_export(real_cats))
        except Exception as e:
            get_app_logger().warning(f"[CF Sync] Failed to fetch IPs from DB: {e}")

    if "timed_out" in categories:
        try:
            from database import get_database

            db = get_database()
            ip_set.update(db.ip_stats.get_timedout_ips(config.ban_duration_seconds))
        except Exception as e:
            get_app_logger().warning(f"[CF Sync] Failed to fetch timed-out IPs: {e}")

    public_ips = [ip for ip in ip_set if is_valid_public_ip(ip, server_ip)]

    if not public_ips:
        get_app_logger().info("[CF Sync] No public IPs to sync")
        return {"status": "ok", "count": 0, "message": "No public IPs to sync"}

    def _find_list_by_name():
        """Search existing lists for one matching the configured name."""
        r = _cf_request(
            "GET",
            f"https://api.cloudflare.com/client/v4/accounts/{account_id}/rules/lists",
            auth_token,
            timeout=15,
        )
        if not r.get("success"):
            return None
        name = cf_config.get("list_name", "krawl_banlist")
        for lst in r.get("result", []):
            if lst.get("name") == name:
                return lst.get("id")
        return None

    def _create_list_and_save():
        cfg = load_config()
        name = cfg.get("cloudflare", {}).get("list_name", "krawl_banlist")
        desc = cfg.get("cloudflare", {}).get(
            "list_description", "IPs banned by Krawl honeypot"
        )
        r = cf_create_list(account_id, auth_token, name, desc)
        if not r.get("success"):
            return None, [e.get("message", str(e)) for e in r.get("errors", [])]
        new_id = r["result"]["id"]
        cfg["cloudflare"]["list_id"] = new_id
        save_config(cfg)
        return new_id, None

    # If no list_id, try to find existing list by name, else create one
    if not list_id:
        found_id = _find_list_by_name()
        if found_id:
            list_id = found_id
            cfg = load_config()
            cfg["cloudflare"]["list_id"] = list_id
            save_config(cfg)
            get_app_logger().info(f"[CF Sync] Using existing list: {list_id}")
        else:
            list_id, err = _create_list_and_save()
            if err:
                return {"status": "error", "error": f"Failed to create list: {err}"}
            get_app_logger().info(f"[CF Sync] Created CF list: {list_id}")

    # Replace all items — if list not found, search by name then create and retry once
    result = cf_replace_items(account_id, auth_token, list_id, public_ips)
    if not result.get("success"):
        err_msgs = [e.get("message", str(e)) for e in result.get("errors", [])]
        if any("not_found" in m or "could not find" in m for m in err_msgs):
            get_app_logger().info(
                f"[CF Sync] List {list_id} not found, searching by name"
            )
            found_id = _find_list_by_name()
            if found_id:
                list_id = found_id
                cfg = load_config()
                cfg["cloudflare"]["list_id"] = list_id
                save_config(cfg)
                get_app_logger().info(f"[CF Sync] Found existing list: {list_id}")
            else:
                list_id, err = _create_list_and_save()
                if err:
                    return {
                        "status": "error",
                        "error": f"List gone, no matching list found, and creation failed: {err}",
                    }
            result = cf_replace_items(account_id, auth_token, list_id, public_ips)
            if not result.get("success"):
                err_msgs = [e.get("message", str(e)) for e in result.get("errors", [])]
                return {
                    "status": "error",
                    "error": f"Failed to replace items: {err_msgs}",
                }
        else:
            return {"status": "error", "error": f"Failed to replace items: {err_msgs}"}

    get_app_logger().info(
        f"[CF Sync] Synced {len(public_ips)} IPs to CF list {list_id}"
    )
    return {"status": "ok", "count": len(public_ips), "list_id": list_id}
