import requests


def get_geo(ip):
    private_prefixes = ("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")

    if ip == "unknown" or ip.startswith(private_prefixes):
        return {
            "country": "LAB",
            "city": "Local Lab",
            "lat": 52.2297,
            "lon": 21.0122
        }

    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=4).json()

        return {
            "country": res.get("country", "Unknown"),
            "city": res.get("city", "Unknown"),
            "lat": res.get("lat", 0),
            "lon": res.get("lon", 0)
        }
    except Exception:
        return {
            "country": "Unknown",
            "city": "Unknown",
            "lat": 0,
            "lon": 0
        }
