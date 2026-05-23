from scapy.all import *
from datetime import datetime

# Packet counter
count = 0

# Common service ports
services = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH"
}

#Blocked Ports#
blocked_ports = [22]


def get_service(port):
    """
    Return service name from port number.
    If unknown, return OTHERS.
    """
    return services.get(port, "OTHERS")


def process_packet(packet):

    global count

    #date time year#
    now = datetime.now()

#formating date and time to D-M-Y H:M:S
    timestamp = now.strftime("%d-%m-%Y %H:%M:%S")

    # Process only IP packets
    if not packet.haslayer(IP):
        return

    count += 1

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
            if dst_port in blocked_ports or src_port in blocked_ports:
                print(
                    f"#{count} [BLOCKED] [TCP][{service}] "
                    f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                )
                with open("firewall.log", "a") as file:
                    file.write(f"#{count} {timestamp} [BLOCKED] [TCP][{service}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} \n")
            else:
                print(
                    f"#{count} [TCP][{service}] "
                    f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                )
                with open("firewall.log", "a") as file:
                    file.write(f"#{count} {timestamp} [TCP][{service}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} \n")

        # ---------------- UDP ----------------
        elif packet.haslayer(UDP):

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            service = get_service(dst_port)

            if service == "OTHERS":
                service = get_service(src_port)
            if dst_port in blocked_ports or src_port in blocked_ports:
                print(
                    f"#{count} [BLOCKED] [UDP][{service}] "
                    f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                )
                with open("firewall.log", "a") as file:
                    file.write(f"#{count} {timestamp} [BLOCKED] [UDP][{service}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} \n")
            else:
                print(
                    f"#{count} [UDP][{service}] "
                    f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                )
                with open("firewall.log", "a") as file:
                    file.write(f"#{count} {timestamp} [UDP][{service}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} \n")

        # ---------------- ICMP ----------------
        elif packet.haslayer(ICMP):

            print(
                f"#{count} [ICMP] "
                f"{src_ip} -> {dst_ip}"
            )
            with open("firewall.log", "a") as file:
                    file.write(f"#{count} {timestamp} [ICMP] {src_ip} -> {dst_ip} \n")

    except Exception as e:
        print(f"[ERROR] {e}")


# Start sniffing
sniff(
    iface="Wi-Fi",
    filter="ip",
    prn=process_packet
)