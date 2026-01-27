from database import get_database
from logger import get_app_logger
import requests
from sanitizer import sanitize_for_storage, sanitize_dict

# ----------------------
# TASK CONFIG
# ----------------------

TASK_CONFIG = {
    "name": "fetch-ip-rep",
    "cron": "*/5 * * * *",
    "enabled": True,
    "run_when_loaded": True,
}


def main():
    db_manager = get_database()
    app_logger = get_app_logger()

    # Only get IPs that haven't been enriched yet
    unenriched_ips = db_manager.get_unenriched_ips(limit=50)
    app_logger.info(
        f"{len(unenriched_ips)} IP's need to be have reputation enrichment."
    )
    for ip in unenriched_ips:
        try:
            api_url = "https://iprep.lcrawl.com/api/iprep/"
            params = {"cidr": ip}
            headers = {"Content-Type": "application/json"}
            response = requests.get(api_url, headers=headers, params=params, timeout=10)
            payload = response.json()

            if payload.get("results"):
                data = payload["results"][0]
                geoip_data = data["geoip_data"]
                country_iso_code = geoip_data.get("country_iso_code")
                asn = geoip_data.get("asn_autonomous_system_number")
                asn_org = geoip_data.get("asn_autonomous_system_organization")
                city = geoip_data.get("city_name")  # Extract city name from API
                list_on = data["list_on"]

                sanitized_country_iso_code = sanitize_for_storage(country_iso_code, 3)
                sanitized_asn = sanitize_for_storage(asn, 100)
                sanitized_asn_org = sanitize_for_storage(asn_org, 100)
                sanitized_city = sanitize_for_storage(city, 100) if city else None
                sanitized_list_on = sanitize_dict(list_on, 100000)

                db_manager.update_ip_rep_infos(
                    ip,
                    sanitized_country_iso_code,
                    sanitized_asn,
                    sanitized_asn_org,
                    sanitized_list_on,
                    sanitized_city,  # Pass city to database
                )
        except requests.RequestException as e:
            app_logger.warning(f"Failed to fetch IP rep for {ip}: {e}")
        except Exception as e:
            app_logger.error(f"Error processing IP {ip}: {e}")
