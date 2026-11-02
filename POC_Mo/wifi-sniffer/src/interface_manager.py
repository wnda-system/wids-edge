import subprocess
import os
import sys

def run_cmd(cmd):
    return subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def require_root():
    if os.geteuid() != 0:
        print("[!] Must run as root")
        sys.exit(1)

def setup_interface(interface, logger):
    require_root()

    # เช็คว่ามี interface จริงไหม
    result = subprocess.run(
        ["ip", "link", "show", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        logger.error(f"Interface {interface} not found")
        sys.exit(1)

    # ตั้ง monitor mode
    run_cmd(["ip", "link", "set", interface, "down"])
    run_cmd(["iw", "dev", interface, "set", "type", "monitor"])
    run_cmd(["ip", "link", "set", interface, "up"])

    logger.info(f"{interface} ready in monitor mode")
