from scapy.all import sniff
import csv, os, time, signal, sys

from logger_config import setup_logger
from interface_manager import setup_interface
from channel_hopper import ChannelHopper
from packet_parser import handle_packet, AWID_HEADERS

INTERFACE = "wlx1cbfce71ebe7"
CHANNELS = [1,6,11,36,40,44,48]
HOP_INTERVAL = 0.3

logger = setup_logger()

print("[*] Manual mode")
print("[*] Setting up interface...")
setup_interface(INTERFACE, logger)

ts = time.strftime("%Y%m%d_%H%M%S")
CSV_FILE = f"../data/manual_wifi_packets_{ts}.csv"
os.makedirs(os.path.dirname(CSV_FILE), exist_ok=True)

# =========================
# CSV SETUP
# =========================

file_is_empty = not os.path.exists(CSV_FILE) or os.path.getsize(CSV_FILE) == 0

csvfile = open(CSV_FILE, "a", newline="", encoding="utf-8")
writer = csv.writer(csvfile)

if file_is_empty:
    writer.writerow(AWID_HEADERS)
    csvfile.flush()

print(f"[*] CSV header fields: {len(AWID_HEADERS)}")

# =========================
# CHANNEL HOPPER
# =========================

hopper = ChannelHopper(INTERFACE, CHANNELS, HOP_INTERVAL, logger)
hopper.start()

# =========================
# STOP HANDLER
# =========================

def stop_handler(sig, frame):
    print("\n[*] Stopping...")
    hopper.stop()
    csvfile.close()
    sys.exit(0)

signal.signal(signal.SIGINT, stop_handler)

logger.info("Manual Wi-Fi Anomaly Sniffer Started")

# =========================
# PACKET CALLBACK
# =========================

def packet_callback(pkt):
    try:
        handle_packet(pkt, writer, logger)
    except Exception as e:
        logger.exception("Packet processing error")

# =========================
# START SNIFF
# =========================

sniff(
    iface=INTERFACE,
    prn=packet_callback,
    store=False
)