import pyshark
import ipaddress
import requests
import socket
from collections import defaultdict
from datetime import datetime

# =========================
# CONFIG
# =========================

INTERFACE = "Wi-Fi"
FILTER = "udp"

# =========================
# COLORS (DARK THEME)
# =========================

RESET = "\033[0m"
WHITE = "\033[97m"
LIGHT_GRAY = "\033[37m"
GRAY = "\033[90m"
BLACK = "\033[30m"
BOLD = "\033[1m"

# accents subtils (gris/white only)
ACCENT = "\033[97m"
DIM = "\033[90m"

# =========================
# DATA
# =========================

ip_count = defaultdict(int)
cache = {}

# =========================
# UTILS
# =========================

def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except:
        return False


def r_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "N/A"


def ip_info(ip):
    if ip in cache:
        return cache[ip]

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,proxy,hosting,mobile",
            timeout=5
        ).json()

        if r["status"] != "success":
            return None

        data = {
            "country": r.get("country"),
            "city": r.get("city"),
            "isp": r.get("isp"),
            "org": r.get("org"),
            "asn": r.get("as"),
            "proxy": r.get("proxy"),
            "hosting": r.get("hosting"),
            "mobile": r.get("mobile"),
            "rdns": r_dns(ip)
        }

        cache[ip] = data
        return data

    except:
        return None


# =========================
# HEADER
# =========================

print(BOLD + WHITE + "\n=====================================")
print("        NETWORK MONITOR")
print("=====================================\n" + RESET)

print(DIM + f"Interface : {INTERFACE}")
print(f"Filter    : {FILTER}\n" + RESET)

print(WHITE + "Status : listening...\n" + RESET)

# =========================
# CAPTURE
# =========================

capture = pyshark.LiveCapture(
    interface=INTERFACE,
    display_filter=FILTER
)

# =========================
# LOOP
# =========================

for packet in capture.sniff_continuously():

    try:
        if not hasattr(packet, "ip"):
            continue

        ip = packet.ip.dst

        if not is_public(ip):
            continue

        ip_count[ip] += 1

        # =========================
        # NEW IP
        # =========================

        if ip_count[ip] == 1:

            print(BOLD + WHITE + "\n-------------------------------------")
            print(" NEW CONNECTION DETECTED")
            print("-------------------------------------" + RESET)

            print(WHITE + f"IP    : {ip}")
            print(DIM + f"Time  : {datetime.now()}" + RESET)

            info = ip_info(ip)

            if info:

                print(WHITE + "\n--- INFO ---" + RESET)
                print(DIM + f"Country : {info['country']}")
                print(f"City    : {info['city']}")
                print(f"ISP     : {info['isp']}")
                print(f"Org     : {info['org']}")
                print(f"ASN     : {info['asn']}")
                print(f"DNS     : {info['rdns']}" + RESET)

                print(DIM + "\n--- FLAGS ---")
                print(f"VPN     : {info['proxy']}")
                print(f"Host    : {info['hosting']}")
                print(f"Mobile  : {info['mobile']}" + RESET)

        # =========================
        # EXISTING IP
        # =========================

        else:
            print(
                GRAY +
                f"[{ip}] packets={ip_count[ip]}" +
                RESET
            )

    except Exception as e:
        print(DIM + f"error: {e}" + RESET)