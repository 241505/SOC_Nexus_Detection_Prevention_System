"""
geoip.py — Real IP Geolocation Module
Uses ip-api.com (free, no key needed, 45 req/min).
Results cached in-memory to respect rate limits and speed up lookups.
"""

import time
import logging
import requests
from config import GEOIP_URL, GEOIP_CACHE_TTL
from utils import is_private_ip, is_valid_ip

logger = logging.getLogger("geoip")

# In-memory cache: { ip: (timestamp, geo_dict) }
_cache: dict = {}

# Placeholder returned for private / invalid IPs
_LOCAL_GEO = {
    "ip":         "local",
    "country":    "Local Network",
    "region":     "Private",
    "city":       "N/A",
    "isp":        "Internal",
    "lat":        0.0,
    "lon":        0.0,
    "status":     "local",
}


def lookup(ip: str) -> dict:
    """
    Return geolocation dict for the given IP.
    Fields: ip, country, region, city, isp, lat, lon, status
    """
    if not is_valid_ip(ip):
        return {**_LOCAL_GEO, "ip": ip}

    if is_private_ip(ip):
        return {**_LOCAL_GEO, "ip": ip}

    # Check cache
    if ip in _cache:
        cached_ts, cached_data = _cache[ip]
        if time.time() - cached_ts < GEOIP_CACHE_TTL:
            return cached_data

    try:
        url = GEOIP_URL.format(ip=ip)
        resp = requests.get(url, timeout=5)
        data = resp.json()

        if data.get("status") == "success":
            geo = {
                "ip":      ip,
                "country": data.get("country", "Unknown"),
                "region":  data.get("regionName", "Unknown"),
                "city":    data.get("city", "Unknown"),
                "isp":     data.get("isp", "Unknown"),
                "lat":     data.get("lat", 0.0),
                "lon":     data.get("lon", 0.0),
                "status":  "success",
            }
        else:
            geo = {
                "ip":      ip,
                "country": "Unknown",
                "region":  "Unknown",
                "city":    "Unknown",
                "isp":     "Unknown",
                "lat":     0.0,
                "lon":     0.0,
                "status":  data.get("status", "fail"),
            }

        _cache[ip] = (time.time(), geo)
        return geo

    except requests.RequestException as exc:
        logger.warning("GeoIP lookup failed for %s: %s", ip, exc)
        return {**_LOCAL_GEO, "ip": ip, "status": "error"}


def bulk_lookup(ips: list) -> dict:
    """Look up a list of IPs; returns dict keyed by IP."""
    result = {}
    for ip in ips:
        result[ip] = lookup(ip)
        time.sleep(0.05)   # Respect 45 req/min free tier
    return result


def get_country_counts(ip_list: list) -> dict:
    """
    Given a list of IP strings, return {country: count} mapping.
    Used for the dashboard geo-chart.
    """
    country_counts = {}
    for ip in ip_list:
        geo = lookup(ip)
        country = geo.get("country", "Unknown")
        country_counts[country] = country_counts.get(country, 0) + 1
    return country_counts