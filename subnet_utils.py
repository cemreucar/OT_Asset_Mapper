from ipaddress import ip_address, ip_network

DEFAULT_ZONES = {
    "OT": ["10.0.0.0/8", "172.16.0.0/12"],
    "IT": ["192.168.0.0/16"],
    "DMZ": [],
    "Vendor": [],
}


def parse_zone_config(text):
    zones = {k: list(v) for k, v in DEFAULT_ZONES.items()}

    if not text or not str(text).strip():
        return zones

    for line in str(text).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        zone, ranges = line.split("=", 1)
        zone = zone.strip()
        cidrs = [x.strip() for x in ranges.split(",") if x.strip()]
        zones[zone] = cidrs

    return zones


def guess_zone(ip, zones=None):
    if zones is None:
        zones = DEFAULT_ZONES

    try:
        ip_obj = ip_address(str(ip).strip())
    except Exception:
        return "Unknown"

    for zone, cidrs in zones.items():
        for cidr in cidrs:
            try:
                if ip_obj in ip_network(cidr, strict=False):
                    return zone
            except Exception:
                continue

    return "Unknown"
