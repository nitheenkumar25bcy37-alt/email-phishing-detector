"""Backward-compatible facade for optional IP intelligence."""

from typing import Any, Dict

from backend.intelligence.ip_provider import IPIntelligenceProvider


class GeoIPMapper:
    _provider = IPIntelligenceProvider()

    @classmethod
    def get_ip_intel(cls, ip: str) -> Dict[str, Any]:
        result = cls._provider.lookup(ip)
        result.setdefault("is_cloud_vps", bool(result.get("cloud_provider") or result.get("hosting_provider")))
        return result
