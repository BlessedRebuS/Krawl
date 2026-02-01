from database import get_database
from logger import get_app_logger
import requests
from sanitizer import sanitize_for_storage, sanitize_dict
from geo_utils import extract_geolocation_from_ip, fetch_blocklist_data

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
            # Fetch geolocation data using ip-api.com
            geoloc_data = extract_geolocation_from_ip(ip)
            
            # Fetch blocklist data from lcrawl API
            blocklist_data = fetch_blocklist_data(ip)

            if geoloc_data:
                # Extract fields from the new API response
                country_iso_code = geoloc_data.get("country_code")
                country = geoloc_data.get("country")
                region = geoloc_data.get("region")
                region_name = geoloc_data.get("region_name")
                city = geoloc_data.get("city")
                timezone = geoloc_data.get("timezone")
                isp = geoloc_data.get("isp")
                reverse = geoloc_data.get("reverse")
                asn = geoloc_data.get("asn")
                asn_org = geoloc_data.get("org")
                latitude = geoloc_data.get("latitude")
                longitude = geoloc_data.get("longitude")
                is_proxy = geoloc_data.get("is_proxy", False)
                is_hosting = geoloc_data.get("is_hosting", False)

                # Use blocklist data if available, otherwise create default with flags
                if blocklist_data:
                    list_on = blocklist_data
                else:
                    list_on = {}
                
                # Add flags to list_on
                list_on["is_proxy"] = is_proxy
                list_on["is_hosting"] = is_hosting

                sanitized_country_iso_code = sanitize_for_storage(country_iso_code, 3)
                sanitized_country = sanitize_for_storage(country, 100)
                sanitized_region = sanitize_for_storage(region, 2)
                sanitized_region_name = sanitize_for_storage(region_name, 100)
                sanitized_asn = sanitize_for_storage(asn, 100)
                sanitized_asn_org = sanitize_for_storage(asn_org, 100)
                sanitized_city = sanitize_for_storage(city, 100) if city else None
                sanitized_timezone = sanitize_for_storage(timezone, 50)
                sanitized_isp = sanitize_for_storage(isp, 100)
                sanitized_reverse = sanitize_for_storage(reverse, 255) if reverse else None
                sanitized_list_on = sanitize_dict(list_on, 100000)

                db_manager.update_ip_rep_infos(
                    ip,
                    sanitized_country_iso_code,
                    sanitized_asn,
                    sanitized_asn_org,
                    sanitized_list_on,
                    city=sanitized_city,
                    latitude=latitude,
                    longitude=longitude,
                    country=sanitized_country,
                    region=sanitized_region,
                    region_name=sanitized_region_name,
                    timezone=sanitized_timezone,
                    isp=sanitized_isp,
                    reverse=sanitized_reverse,
                    is_proxy=is_proxy,
                    is_hosting=is_hosting,
                )
        except requests.RequestException as e:
            app_logger.warning(f"Failed to fetch geolocation for {ip}: {e}")
        except Exception as e:
            app_logger.error(f"Error processing IP {ip}: {e}")
