import subprocess
import sys

def block_ip(ip_addr):
    
    command = ["sudo", "iptables", "-A", "INPUT", "-s", ip_addr, "-j", "DROP"]

    try:
        
        result = subprocess.run(command, check=True, text=True, capture_output=True)
        print(f"The IP:{ip_addr} Successfully Blocked")

    except subprocess.CalledProcessError as e:

        print(f"Error executing iptables: {e.stderr}", file=sys.stderr)

