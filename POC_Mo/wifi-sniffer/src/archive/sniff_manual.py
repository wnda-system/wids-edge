from scapy.all import sniff, RadioTap
from scapy.layers.dot11 import Dot11, Dot11QoS, Dot11Beacon, Dot11Elt
import csv, time, os, threading, subprocess, signal, sys
from collections import defaultdict

from logger_config import setup_logger
from interface_manager import setup_interface


# ================= CONFIG =================
INTERFACE = "wlx1cbfce71ebe7"

CHANNELS = [1,6,11,36,40,44,48]
HOP_INTERVAL = 0.3
# ==========================================

logger = setup_logger()
ts_file = time.strftime("%Y%m%d_%H%M%S")
CSV_FILE = f"../data/anomaly_wifi_packets_{ts_file}.csv"

setup_interface(INTERFACE, logger)

os.makedirs(os.path.dirname(CSV_FILE), exist_ok=True)
file_exists = os.path.isfile(CSV_FILE)

csvfile = open(CSV_FILE, "a", newline="", encoding="utf-8")
writer = csv.writer(csvfile)

if not file_exists:
    writer.writerow([
        "timestamp_epoch",
        "inter_arrival_time",
        "channel","freq",
        "type","subtype",
        "src_mac","dst_mac","bssid","ssid",
        "rssi","noise","antenna",
        "data_rate","mcs",
        "frame_len","sequence",
        "sequence_gap",
        "retry","to_ds","from_ds",
        "qos_tid",
        "beacon_interval",
        "capability",
        "rsn_info",
        "supported_rates",
        "ht_capable",
        "vht_capable"
    ])

stop_event = threading.Event()
last_packet_time = None
last_sequence = defaultdict(lambda: None)

# ================= Channel Hopper =================
def set_channel(ch):
    subprocess.run(
        ["iw", "dev", INTERFACE, "set", "channel", str(ch)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def channel_hopper():
    while not stop_event.is_set():
        for ch in CHANNELS:
            if stop_event.is_set():
                break
            set_channel(ch)
            time.sleep(HOP_INTERVAL)

# ================= Packet Handler =================
def handle(pkt):
    global last_packet_time

    if not pkt.haslayer(Dot11):
        return

    try:
        now = time.time()
        inter_arrival = None
        if last_packet_time:
            inter_arrival = now - last_packet_time
        last_packet_time = now

        dot11 = pkt[Dot11]

        src = dot11.addr2
        dst = dot11.addr1
        bssid = dot11.addr3
        ftype = dot11.type
        fsub = dot11.subtype
        frame_len = len(pkt)

        fc = dot11.FCfield
        retry = bool(fc & 0x08)
        to_ds = bool(fc & 0x01)
        from_ds = bool(fc & 0x02)

        sequence = None
        sequence_gap = None

        sc = getattr(dot11, "SC", None)

        if sc is not None:
            sequence = sc >> 4

            key = src or bssid
            if key:
                if last_sequence[key] is not None:
                    sequence_gap = sequence - last_sequence[key]
                last_sequence[key] = sequence

        qos_tid = None
        if pkt.haslayer(Dot11QoS):
            qos_tid = pkt[Dot11QoS].TID

        ssid = None
        beacon_interval = None
        capability = None
        rsn_info = None
        supported_rates = []
        ht_capable = False
        vht_capable = False

        if pkt.haslayer(Dot11Beacon):
            beacon = pkt[Dot11Beacon]
            beacon_interval = beacon.beacon_interval
            capability = beacon.cap

        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:
                ssid = elt.info.decode(errors="ignore")
            elif elt.ID == 1:
                supported_rates = list(elt.info)
            elif elt.ID == 48:
                rsn_info = elt.info.hex()
            elif elt.ID == 45:
                ht_capable = True
            elif elt.ID == 191:
                vht_capable = True
            elt = elt.payload.getlayer(Dot11Elt)

        rssi = noise = antenna = rate = mcs = channel = freq = None
        if pkt.haslayer(RadioTap):
            rt = pkt[RadioTap]
            rssi = getattr(rt, "dBm_AntSignal", None)
            noise = getattr(rt, "dBm_AntNoise", None)
            antenna = getattr(rt, "Antenna", None)
            rate = getattr(rt, "Rate", None)
            freq = getattr(rt, "ChannelFrequency", None)
            mcs = getattr(rt, "MCS", None)
            channel = getattr(rt, "Channel", None)

        writer.writerow([
            now,
            inter_arrival,
            channel, freq,
            ftype, fsub,
            src, dst, bssid, ssid,
            rssi, noise, antenna,
            rate, mcs,
            frame_len, sequence,
            sequence_gap,
            retry, to_ds, from_ds,
            qos_tid,
            beacon_interval,
            capability,
            rsn_info,
            supported_rates,
            ht_capable,
            vht_capable
        ])

    except Exception:
        logger.exception("Packet processing error")

# ================= Shutdown =================
def signal_handler(sig, frame):
    logger.info("Stopping sniffer...")
    stop_event.set()
    time.sleep(0.5)
    csvfile.close()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ================= START =================
logger.info("Wi-Fi anomaly sniffer started (^C to stop)")

hopper = threading.Thread(target=channel_hopper)
hopper.daemon = True
hopper.start()

sniff(
    iface=INTERFACE,
    prn=handle,
    store=False
)
