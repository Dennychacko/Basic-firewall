from scapy.all import *
from datetime import datetime

import config

from services import get_service
from logger import log_packet
from iptables_manager import block_ip


ip_packet_count = {}

blocked_ip = set()

PACKET_THRESHOLD = 100;

def process_packet(packet):

    # Generate timestamp for each packet
    timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    # Process only IP packets
    if not packet.haslayer(IP):
        return

    # Increase packet count
    config.count += 1

    # IP information
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    try:

        # ---------------- TCP ---------------- #
        if packet.haslayer(TCP):

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # Detect service
            service = get_service(dst_port)

            # If destination unknown, try source port
            if service == "OTHERS":
                service = get_service(src_port)

            #counting specific ip address packets
            if src_ip not in ip_packet_count:
                ip_packet_count[src_ip] = 1
            else:
                ip_packet_count[src_ip] += 1

            #checking if THRESHOLD meets
            if (ip_packet_count[src_ip] > PACKET_THRESHOLD and src_ip not in block_ip):
                print(f"[SUSPICIOUS] {src_ip}"
                      f"sent {ip_packet_count[src_ip]} packets")
                try:
                    block_ip(src_ip)
                except:
                    print(f"Not Blocked [ERROR 441]")
            

            # Check blocked ports
            if (
                dst_port in config.blocked_ports
                or src_port in config.blocked_ports
            ):

                message = (
                    f"#{config.count} {timestamp} "
                    f"[BLOCKED] [TCP][{service}] "
                    f"{src_ip}:{src_port} -> "
                    f"{dst_ip}:{dst_port}"
                )

                print(message)
                log_packet(message)

            else:

                message = (
                    f"#{config.count} {timestamp} "
                    f"[TCP][{service}] "
                    f"{src_ip}:{src_port} -> "
                    f"{dst_ip}:{dst_port}"
                )

                print(message)
                log_packet(message)

        # ---------------- UDP ---------------- #
        elif packet.haslayer(UDP):

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            # Detect service
            service = get_service(dst_port)

            if service == "OTHERS":
                service = get_service(src_port)

            #counting specific ip address packets
            if src_ip not in ip_packet_count:
                ip_packet_count[src_ip] = 1
            else:
                ip_packet_count[src_ip] += 1

            #checking if THRESHOLD meets
            if (ip_packet_count[src_ip] > PACKET_THRESHOLD and src_ip not in block_ip):
                print(f"[SUSPICIOUS] {src_ip}"
                      f"sent {ip_packet_count[src_ip]} packets")
                try:
                    block_ip(src_ip)
                except:
                    print(f"Not Blocked [ERROR 441]")


            # Check blocked ports
            if (
                dst_port in config.blocked_ports
                or src_port in config.blocked_ports
            ):

                message = (
                    f"#{config.count} {timestamp} "
                    f"[BLOCKED] [UDP][{service}] "
                    f"{src_ip}:{src_port} -> "
                    f"{dst_ip}:{dst_port}"
                )

                print(message)
                log_packet(message)

            else:

                message = (
                    f"#{config.count} {timestamp} "
                    f"[UDP][{service}] "
                    f"{src_ip}:{src_port} -> "
                    f"{dst_ip}:{dst_port}"
                )

                print(message)
                log_packet(message)

        # ---------------- ICMP ---------------- #
        elif packet.haslayer(ICMP):

            message = (
                f"#{config.count} {timestamp} "
                f"[ICMP] "
                f"{src_ip} -> {dst_ip}"
            )

            print(message)
            log_packet(message)

    except Exception as e:
        print(f"[ERROR] {e}")