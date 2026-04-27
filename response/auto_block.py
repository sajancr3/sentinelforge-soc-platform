import subprocess
import os

BLOCK_LOG = "response/blocked_ips.txt"

def block_ip(ip):
    try:
        # Avoid blocking localhost or internal
        if ip.startswith("127.") or ip.startswith("192.168"):
            return "[SKIPPED] Internal IP"

        # Check if already blocked
        if os.path.exists(BLOCK_LOG):
            with open(BLOCK_LOG, "r") as f:
                if ip in f.read():
                    return "[SKIPPED] Already blocked"

        # Block using iptables
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)

        # Log blocked IP
        with open(BLOCK_LOG, "a") as f:
            f.write(ip + "\n")

        return "[BLOCKED] IP successfully blocked"

    except Exception as e:
        return f"[ERROR] {str(e)}"
