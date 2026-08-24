import os
import json
import requests
from typing import Optional, Dict

class GeoIPMapper:
    """Geolocates origin IPs and detects suspicious cloud/VPN hosting providers."""
    
    CACHE_DIR = "data/geoip_cache"
    
    # Common cloud VPS/hosting ASNs used by attackers to launch phishing
    CLOUD_HOSTING_KEYWORDS = [
        "digitalocean", "amazon", "aws", "linode", "ovh", 
        "hetzner", "choopa", "vultr", "alibaba", "m247", "hostinger"
    ]

    @staticmethod
    def get_ip_intel(ip: str) -> Optional[Dict]:
        if not ip or ip == "Unknown":
            return None
            
        os.makedirs(GeoIPMapper.CACHE_DIR, exist_ok=True)
        cache_file = os.path.join(GeoIPMapper.CACHE_DIR, f"{ip}.json")

        # 1. Read from local cache if already queried
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass

        # 2. Query free ip-api endpoint
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,message,country,city,lat,lon,isp,org,as,timezone",
                timeout=5
            )
            data = response.json()
            if data.get("status") != "success":
                return None

            org_isp = f"{data.get('org', '')} {data.get('isp', '')} {data.get('as', '')}".lower()
            is_cloud_vps = any(provider in org_isp for provider in GeoIPMapper.CLOUD_HOSTING_KEYWORDS)

            intel = {
                "ip": ip,
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "latitude": data.get("lat", 0.0),
                "longitude": data.get("lon", 0.0),
                "isp": data.get("isp", "Unknown"),
                "organization": data.get("org", "Unknown"),
                "asn": data.get("as", "Unknown"),
                "timezone": data.get("timezone", "Unknown"),
                "is_cloud_vps": is_cloud_vps
            }

            # Cache the result to prevent redundant API queries
            with open(cache_file, 'w') as f:
                json.dump(intel, f)

            return intel
        except Exception:
            return None
