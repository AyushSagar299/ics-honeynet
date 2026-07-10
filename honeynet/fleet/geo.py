"""
geo.py -- turn an IP address into a location, offline.

Uses geoip2fast, which ships its own small database, so there is no API key and
nothing is sent to the internet (important: we must not leak attacker IPs to an
outside service). Localhost and private-range IPs are labelled as "Local",
because they have no real-world location.
"""

from geoip2fast import GeoIP2Fast

_geo = GeoIP2Fast()


def flag_emoji(country_code):
    """Two-letter country code -> flag emoji (e.g. 'US' -> the US flag)."""
    cc = (country_code or "").strip().upper()
    if len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc)


def locate(ip):
    """Return {country_code, country, flag, is_local} for an IP."""
    try:
        r = _geo.lookup(ip)
        cc = (r.country_code or "").strip()
        name = r.country_name or "Unknown"
    except Exception:
        return {"country_code": "", "country": "Unknown", "flag": "", "is_local": False}

    is_local = cc in ("", "--")           # geoip2fast marks local/private ranges as "--"
    return {
        "country_code": "" if is_local else cc,
        "country": name,                  # "Localhost" / "Private Network ..." for local
        "flag": "" if is_local else flag_emoji(cc),
        "is_local": is_local,
    }
