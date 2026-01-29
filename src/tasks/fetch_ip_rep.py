from database import get_database
from logger import get_app_logger
import requests
from sanitizer import sanitize_for_storage, sanitize_dict
from geo_utils import get_most_recent_geoip_data, extract_city_from_coordinates

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
                results = payload["results"]

                # Get the most recent result (first in list, sorted by record_added)
                most_recent = results[0]
                geoip_data = most_recent.get("geoip_data", {})
                list_on = most_recent.get("list_on", {})

                # Extract standard fields
                country_iso_code = geoip_data.get("country_iso_code")
                asn = geoip_data.get("asn_autonomous_system_number")
                asn_org = geoip_data.get("asn_autonomous_system_organization")
                latitude = geoip_data.get("location_latitude")
                longitude = geoip_data.get("location_longitude")

                # Extract city from coordinates using reverse geocoding
                city = extract_city_from_coordinates(geoip_data)

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
                    sanitized_city,
                    latitude,
                    longitude,
                )
        except requests.RequestException as e:
            app_logger.warning(f"Failed to fetch IP rep for {ip}: {e}")
        except Exception as e:
            app_logger.error(f"Error processing IP {ip}: {e}")
