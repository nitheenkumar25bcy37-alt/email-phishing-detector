import sys
from pathlib import Path

# Add the project root directory to Python's search path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.header_analyzer import HeaderAnalyzer
from backend.domain_intel import DomainIntelEngine
from backend.geoip_mapper import GeoIPMapper

# Sample raw headers mimicking a phishing attempt
sample_headers = """Received: from mail.phishinghost.net (185.220.101.5) by mx.google.com with SMTP id xyz123;
    Sun, 23 Aug 2026 14:00:00 +0000
Received: from internal.host (192.168.1.100) by mail.phishinghost.net;
    Sun, 23 Aug 2026 14:05:00 +0000
From: Security Alert <security@google.com>
Subject: Critical Account Update
"""

print("=== 1. Header Forensics ===")
origin_ip = HeaderAnalyzer.extract_origin_ip(sample_headers)
anomalies = HeaderAnalyzer.detect_timestamp_anomalies(sample_headers)
print(f"Origin IP Identified: {origin_ip}")
print(f"Relay Anomalies: {anomalies}\n")

print("=== 2. GeoIP & Infrastructure Intel ===")
if origin_ip:
    geo_data = GeoIPMapper.get_ip_intel(origin_ip)
    if geo_data:
        print(f"Location: {geo_data.get('city')}, {geo_data.get('country')}")
        print(f"ISP / ASN: {geo_data.get('isp')} ({geo_data.get('asn')})")
        print(f"Is Cloud/VPS Node: {geo_data.get('is_cloud_vps')}\n")
    else:
        print("GeoIP lookup returned no data.\n")

print("=== 3. Domain Intelligence ===")
domain_data = DomainIntelEngine.inspect_domain("google.com")
print(f"Domain: {domain_data.get('domain')}")
print(f"Age (Days): {domain_data.get('domain_age_days')}")
print(f"Has Valid MX: {domain_data.get('has_valid_mx')}")
print(f"Risk Flags: {domain_data.get('risk_flags')}")
