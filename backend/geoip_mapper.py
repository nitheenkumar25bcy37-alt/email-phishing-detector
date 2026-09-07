import json
import os
import re
from pathlib import Path
from typing import Optional, Dict

import requests


class GeoIPMapper:
    CACHE_DIR = Path("data/geoip_cache")
    CLOUD_HOSTING_KEYWORDS = [
        "digitalocean", "amazon", "aws", "linode", "ovh", "hetzner",
        "choopa", "vultr", "alibaba", "m247", "hostinger",
    ]

    @classmethod
    def get_ip_intel(cls, ip: str) -> Optional[Dict]:
        if not ip or ip == "Unknown":
            return None

        if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
            return None

        cls.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_file = cls.CACHE_DIR / f"{ip}.json"
        if cache_file.exists():
            try:
                return json.loads(cache_file.read_text(encoding="utf-8"))
            except Exception:
                pass

        try:
            r = requests.get(
                f"https://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,city,lat,lon,isp,org,as,timezone"},
                timeout=4,
            )
            data = r.json()
            if data.get("status") != "success":
                return None
            combined = f"{data.get('org','')} {data.get('isp','')} {data.get('as','')}".lower()
            result = {
                "ip": ip,
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "isp": data.get("isp", "Unknown"),
                "organization": data.get("org", "Unknown"),
                "asn": data.get("as", "Unknown"),
                "timezone": data.get("timezone", "Unknown"),
                "is_cloud_vps": any(x in combined for x in cls.CLOUD_HOSTING_KEYWORDS),
            }
            cache_file.write_text(json.dumps(result), encoding="utf-8")
            return result
        except Exception:
            return None
