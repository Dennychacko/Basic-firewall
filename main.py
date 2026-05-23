from scapy.all import sniff
from packet_handler import process_packet

# Start sniffing
sniff(
    iface="Wi-Fi",
    filter="ip",
    prn=process_packet
)