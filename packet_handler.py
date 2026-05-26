from scapy.all import *
from datetime import datetime

import config

from colorama import Fore, Style, init

from services import get_service
from logger import log_packet
from iptables_manager import block_ip


# Initialize colorama
init(autoreset=True)


# ---------------- TRACKING ---------------- #

# Count packets per IP
ip_packet_count = {}

# Store already blocked IPs
blocked_ips = set()

# Suspicious threshold
PACKET_THRESHOLD = 100


# Trusted IPs (never auto-block)
trusted_ips = {
    "127.0.0.1",
    "0.0.0.0"
}


# ---------------- HELPER FUNCTIONS ---------------- #

def track_ip(src_ip):
    """
    Count packets per source IP
    """

    if src_ip not in ip_packet_count:
        ip_packet_count[src_ip] = 1
    else:
        ip_packet_count[src_ip] += 1

    return ip_packet_count[src_ip]


def detect_and_block(src_ip):
    """
    Detect suspicious traffic and auto-block IP
    """

    # Ignore trusted IPs
    if src_ip in trusted_ips:
        return

    # Ignore already blocked IPs
    if src_ip in blocked_ips:
        return

    # Check threshold
    if ip_packet_count[src_ip] > PACKET_THRESHOLD:

        print(
            Fore.RED
            + f"[SUSPICIOUS] {src_ip} "
            f"sent {ip_packet_count[src_ip]} packets"
        )

        try:

            block_ip(src_ip)

            blocked_ips.add(src_ip)

            log_packet(
                f"[AUTO BLOCKED] {src_ip} "
                f"after {ip_packet_count[src_ip]} packets"
            )

        except Exception as e:

            print(Fore.RED + f"[BLOCK ERROR] {e}")


def check_blocked_port(src_port, dst_port):
    """
    Check if either source or destination port is blocked
    """

    return (
        src_port in config.blocked_ports
        or dst_port in config.blocked_ports
    )


# ---------------- MAIN PACKET HANDLER ---------------- #

def process_packet(packet):

    # Process only IP packets
    if not packet.haslayer(IP):
        return

    # Generate timestamp
    timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    # Increase packet count
    config.count += 1

    # Extract IPs
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    try:

        # ====================================================
        # TCP
        # ====================================================

        if packet.haslayer(TCP):

            protocol = "TCP"

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # Detect service
            service = get_service(dst_port)

            if service == "OTHERS":
                service = get_service(src_port)

            # Track packets
            track_ip(src_ip)

            # Detect suspicious activity
            detect_and_block(src_ip)

            # Check blocked ports
            is_blocked = check_blocked_port(
                src_port,
                dst_port
            )

            # BLOCKED TCP
            if is_blocked:

                message = (
                    f"#{config.count} {timestamp} "
                    + Fore.RED
                    + f"[BLOCKED] [{protocol}][{service}] "
                    + Fore.WHITE
                    + f"{src_ip}:{src_port} -> "
                    + Fore.CYAN
                    + f"{dst_ip}:{dst_port}"
                )

            # NORMAL TCP
            else:

                message = (
                    f"#{config.count} {timestamp} "
                    + Fore.GREEN
                    + f"[{protocol}][{service}] "
                    + Fore.WHITE
                    + f"{src_ip}:{src_port} -> "
                    + Fore.CYAN
                    + f"{dst_ip}:{dst_port}"
                )

            print(message)
            log_packet(message)

        # ====================================================
        # UDP
        # ====================================================

        elif packet.haslayer(UDP):

            protocol = "UDP"

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            # Detect service
            service = get_service(dst_port)

            if service == "OTHERS":
                service = get_service(src_port)

            # Track packets
            track_ip(src_ip)

            # Detect suspicious activity
            detect_and_block(src_ip)

            # Check blocked ports
            is_blocked = check_blocked_port(
                src_port,
                dst_port
            )

            # BLOCKED UDP
            if is_blocked:

                message = (
                    f"#{config.count} {timestamp} "
                    + Fore.RED
                    + f"[BLOCKED] [{protocol}][{service}] "
                    + Fore.WHITE
                    + f"{src_ip}:{src_port} -> "
                    + Fore.CYAN
                    + f"{dst_ip}:{dst_port}"
                )

            # NORMAL UDP
            else:

                message = (
                    f"#{config.count} {timestamp} "
                    + Fore.YELLOW
                    + f"[{protocol}][{service}] "
                    + Fore.WHITE
                    + f"{src_ip}:{src_port} -> "
                    + Fore.CYAN
                    + f"{dst_ip}:{dst_port}"
                )

            print(message)
            log_packet(message)

        # ====================================================
        # ICMP
        # ====================================================

        elif packet.haslayer(ICMP):

            # Track packets
            track_ip(src_ip)

            # Detect suspicious activity
            detect_and_block(src_ip)

            message = (
                f"#{config.count} {timestamp} "
                + Fore.MAGENTA
                + "[ICMP] "
                + Fore.WHITE
                + f"{src_ip} -> {dst_ip}"
            )

            print(message)
            log_packet(message)

    except Exception as e:

        print(Fore.RED + f"[ERROR] {e}")