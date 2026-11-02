from scapy.all import sniff
import csv, os, time, sys

from logger_config import setup_logger
from interface_manager import setup_interface
from channel_hopper import ChannelHopper
from packet_parser import handle_packet

INTERFACE = "wlx1cbfce71ebe7"
CHANNELS = [1,6,11,36,40,44,48]
HOP_INTERVAL = 0.3
CAPTURE_DURATION = 10   # วินาที

logger = setup_logger()

# -------- Setup Interface --------
setup_interface(INTERFACE, logger)

# -------- CSV --------
ts = time.strftime("%Y%m%d_%H%M%S")
CSV_FILE = f"../data/manual_wifi_packets_{ts}.csv"
os.makedirs(os.path.dirname(CSV_FILE), exist_ok=True)

file_is_empty = not os.path.exists(CSV_FILE) or os.path.getsize(CSV_FILE) == 0

csvfile = open(CSV_FILE, "a", newline="", encoding="utf-8")
writer = csv.writer(csvfile)

# -------- Channel Hopper --------
hopper = ChannelHopper(INTERFACE, CHANNELS, HOP_INTERVAL, logger)
hopper.start()

logger.info(f"Sniffing for {CAPTURE_DURATION} seconds...")

# -------- Sniff (10 วินาที) --------
sniff(
    iface=INTERFACE,
    prn=lambda pkt: handle_packet(pkt, writer, logger),
    store=False,
    timeout=CAPTURE_DURATION
)

# -------- Cleanup --------
logger.info("Capture finished. Cleaning up...")

hopper.stop()
time.sleep(0.5)
csvfile.close()

logger.info("Sniffer stopped cleanly.")
sys.exit(0)
