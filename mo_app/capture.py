"""
capture.py — packet capture + raw field extraction for the WiFi Capture POC.

Two capture backends:
  - real:      uses scapy.sniff() on a monitor-mode interface
  - simulate:  generates synthetic packet rows (no hardware needed) — used for
               testing the app end-to-end and as a demo mode when no adapter
               is attached.

Extracted columns follow wifi_capture_poc_spec.md "Fields to attempt extracting".
Any field that can't be pulled from a given packet is written as -1.
"""

import csv
import os
import random
import shutil
import subprocess
import threading
import time
import uuid

# ---------------------------------------------------------------------------
# Column schema (order is the CSV column order)
# ---------------------------------------------------------------------------

FIELD_ORDER = [
    # frame
    "frame.number", "frame.time_epoch", "frame.len", "frame.time_delta", "frame.encap_type",
    # wlan / radiotap
    "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.retry", "wlan.fc.protected",
    "wlan.duration", "wlan.seq", "wlan.ssid", "wlan.da",
    "radiotap.channel.freq", "radiotap.datarate", "wlan_radio.signal_dbm",
    # arp
    "arp.opcode", "arp.hw.type", "arp.proto.type",
    # eapol
    "eapol.type", "eapol.len", "eapol.keydes.key_len",
    # ip
    "ip.version",
    # tcp
    "tcp.flags.ack", "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.reset",
    "tcp.flags.push", "tcp.analysis.retransmission",
    # dns
    "dns.flags.response", "dns.count.queries", "dns.count.answers",
    # http
    "http.request.method", "http.response.code",
    # presence-only flags for protocols with no single named raw field in the spec
    "dhcp.present", "smb.present", "smb2.present", "ssh.present",
    "tls.present", "mdns.present", "nbss.present", "icmpv6.present",
]

MISSING = -1

PORT_PRESENCE = {
    "dhcp.present": (67, 68),
    "smb.present": (445,),
    "smb2.present": (445,),
    "ssh.present": (22,),
    "tls.present": (443,),
    "mdns.present": (5353,),
    "nbss.present": (139,),
}


# ---------------------------------------------------------------------------
# Monitor-mode check (real capture only)
# ---------------------------------------------------------------------------

def check_monitor_mode(iface: str):
    """Return (ok: bool, message: str)."""
    if shutil.which("iw") is None:
        return False, "The 'iw' command is not installed — cannot verify monitor mode."
    try:
        out = subprocess.run(
            ["iw", "dev", iface, "info"], capture_output=True, text=True, timeout=5
        )
    except FileNotFoundError:
        return False, "The 'iw' command is not installed — cannot verify monitor mode."
    except subprocess.TimeoutExpired:
        return False, f"Timed out querying interface '{iface}'."

    if out.returncode != 0:
        return False, f"Interface '{iface}' not found. Is it up? ({out.stderr.strip()})"

    if "type monitor" not in out.stdout:
        return False, (
            f"Interface '{iface}' exists but is not in monitor mode. "
            f"Put it into monitor mode first (e.g. 'sudo airmon-ng start wlan1')."
        )
    return True, "ok"


# ---------------------------------------------------------------------------
# Real field extraction (scapy)
# ---------------------------------------------------------------------------

def _get(obj, attr, default=MISSING):
    try:
        val = getattr(obj, attr)
        return default if val is None else val
    except Exception:
        return default


def extract_fields(pkt, frame_number, first_time, prev_time):
    """Extract the raw fields listed in FIELD_ORDER from a scapy packet."""
    from scapy.all import Dot11, RadioTap, Dot11Elt, ARP, IP, TCP, DNS

    row = {k: MISSING for k in FIELD_ORDER}

    t = float(pkt.time) if getattr(pkt, "time", None) is not None else MISSING
    row["frame.number"] = frame_number
    row["frame.time_epoch"] = t
    try:
        row["frame.len"] = len(bytes(pkt))
    except Exception:
        row["frame.len"] = MISSING
    row["frame.time_delta"] = (t - prev_time) if (prev_time is not None and t != MISSING) else 0.0

    has_radiotap = pkt.haslayer(RadioTap)
    has_dot11 = pkt.haslayer(Dot11)
    if has_radiotap:
        row["frame.encap_type"] = 127  # DLT_IEEE802_11_RADIO
    elif has_dot11:
        row["frame.encap_type"] = 105  # DLT_IEEE802_11
    else:
        row["frame.encap_type"] = MISSING

    if has_dot11:
        d11 = pkt[Dot11]
        row["wlan.fc.type"] = _get(d11, "type")
        row["wlan.fc.subtype"] = _get(d11, "subtype")
        fc = _get(d11, "FCfield", None)
        if isinstance(fc, int):
            row["wlan.fc.retry"] = 1 if (fc & 0x08) else 0
            row["wlan.fc.protected"] = 1 if (fc & 0x40) else 0
        row["wlan.duration"] = _get(d11, "ID")
        sc = _get(d11, "SC", None)
        row["wlan.seq"] = (sc >> 4) if isinstance(sc, int) else MISSING
        row["wlan.da"] = _get(d11, "addr1")

        # SSID lives in a Dot11Elt (ID=0) tag, typically on beacon/probe frames
        elt = pkt.getlayer(Dot11Elt)
        while elt is not None:
            if getattr(elt, "ID", None) == 0:
                try:
                    row["wlan.ssid"] = elt.info.decode(errors="replace")
                except Exception:
                    row["wlan.ssid"] = MISSING
                break
            elt = elt.payload.getlayer(Dot11Elt)

    if has_radiotap:
        rt = pkt[RadioTap]
        freq = _get(rt, "ChannelFrequency", None)
        row["radiotap.channel.freq"] = freq if freq is not None else MISSING
        rate = _get(rt, "Rate", None)
        row["radiotap.datarate"] = rate if rate is not None else MISSING
        signal = _get(rt, "dBm_AntSignal", None)
        row["wlan_radio.signal_dbm"] = signal if signal is not None else MISSING

    if pkt.haslayer(ARP):
        a = pkt[ARP]
        row["arp.opcode"] = _get(a, "op")
        row["arp.hw.type"] = _get(a, "hwtype")
        row["arp.proto.type"] = _get(a, "ptype")

    try:
        from scapy.layers.eap import EAPOL
        if pkt.haslayer(EAPOL):
            e = pkt[EAPOL]
            row["eapol.type"] = _get(e, "type")
            row["eapol.len"] = _get(e, "len")
            row["eapol.keydes.key_len"] = _get(e, "key_length", MISSING)
    except ImportError:
        pass

    if pkt.haslayer(IP):
        row["ip.version"] = _get(pkt[IP], "version")

    if pkt.haslayer(TCP):
        t_ = pkt[TCP]
        flags = str(_get(t_, "flags", ""))
        row["tcp.flags.ack"] = 1 if "A" in flags else 0
        row["tcp.flags.syn"] = 1 if "S" in flags else 0
        row["tcp.flags.fin"] = 1 if "F" in flags else 0
        row["tcp.flags.reset"] = 1 if "R" in flags else 0
        row["tcp.flags.push"] = 1 if "P" in flags else 0
        # crude retransmission heuristic (not a full Wireshark-equivalent analysis)
        row["tcp.analysis.retransmission"] = MISSING

    if pkt.haslayer(DNS):
        dns_ = pkt[DNS]
        row["dns.flags.response"] = _get(dns_, "qr")
        row["dns.count.queries"] = _get(dns_, "qdcount")
        row["dns.count.answers"] = _get(dns_, "ancount")

    try:
        from scapy.layers.http import HTTPRequest, HTTPResponse
        if pkt.haslayer(HTTPRequest):
            m = _get(pkt[HTTPRequest], "Method", None)
            row["http.request.method"] = m.decode() if isinstance(m, bytes) else (m or MISSING)
        if pkt.haslayer(HTTPResponse):
            c = _get(pkt[HTTPResponse], "Status_Code", None)
            row["http.response.code"] = c.decode() if isinstance(c, bytes) else (c or MISSING)
    except ImportError:
        pass

    # Port-based presence flags for protocols without a single spec'd raw field
    sport = dport = None
    if pkt.haslayer(TCP):
        sport, dport = _get(pkt[TCP], "sport"), _get(pkt[TCP], "dport")
    else:
        try:
            from scapy.all import UDP
            if pkt.haslayer(UDP):
                sport, dport = _get(pkt[UDP], "sport"), _get(pkt[UDP], "dport")
        except ImportError:
            pass
    ports = {p for p in (sport, dport) if isinstance(p, int)}
    for col, port_set in PORT_PRESENCE.items():
        row[col] = 1 if ports & set(port_set) else MISSING

    try:
        from scapy.all import ICMPv6Unknown, IPv6
        if pkt.haslayer(IPv6) and pkt.haslayer(ICMPv6Unknown):
            row["icmpv6.present"] = 1
    except Exception:
        pass

    return row


# ---------------------------------------------------------------------------
# Simulated (mock) capture — no hardware required
# ---------------------------------------------------------------------------

_SSIDS = ["HomeNet", "ASUS", "CoffeeShop_Guest", "Office5G"]
_MACS = lambda: ":".join(f"{random.randint(0,255):02x}" for _ in range(6))


def generate_mock_row(frame_number, t0, prev_time):
    t = (prev_time if prev_time is not None else t0) + random.uniform(0.01, 0.2)
    row = {k: MISSING for k in FIELD_ORDER}
    row["frame.number"] = frame_number
    row["frame.time_epoch"] = t
    row["frame.len"] = random.randint(60, 1500)
    row["frame.time_delta"] = (t - prev_time) if prev_time is not None else 0.0
    row["frame.encap_type"] = 127

    kind = random.choices(
        ["beacon", "data", "arp", "tcp", "dns"], weights=[3, 3, 1, 2, 1]
    )[0]

    row["wlan.fc.type"] = 0 if kind == "beacon" else 2
    row["wlan.fc.subtype"] = 8 if kind == "beacon" else 0
    row["wlan.fc.retry"] = random.choice([0, 1])
    row["wlan.fc.protected"] = random.choice([0, 1])
    row["wlan.duration"] = random.randint(0, 400)
    row["wlan.seq"] = frame_number % 4096
    row["wlan.da"] = _MACS()
    row["radiotap.channel.freq"] = random.choice([2412, 2437, 2462, 5180])
    row["radiotap.datarate"] = random.choice([1, 6, 24, 54])
    row["wlan_radio.signal_dbm"] = -random.randint(30, 90)

    if kind == "beacon":
        row["wlan.ssid"] = random.choice(_SSIDS)
    if kind == "arp":
        row["arp.opcode"] = random.choice([1, 2])
        row["arp.hw.type"] = 1
        row["arp.proto.type"] = 0x0800
    if kind == "tcp":
        row["ip.version"] = 4
        row["tcp.flags.ack"] = random.choice([0, 1])
        row["tcp.flags.syn"] = random.choice([0, 1])
        row["tcp.flags.fin"] = 0
        row["tcp.flags.reset"] = 0
        row["tcp.flags.push"] = random.choice([0, 1])
        if random.random() < 0.1:
            row["http.request.method"] = random.choice(["GET", "POST"])
        if random.random() < 0.1:
            row["http.response.code"] = random.choice([200, 404])
        if random.random() < 0.15:
            row["tls.present"] = 1
    if kind == "dns":
        row["ip.version"] = 4
        row["dns.flags.response"] = random.choice([0, 1])
        row["dns.count.queries"] = 1
        row["dns.count.answers"] = random.choice([0, 1, 2])

    return row


# ---------------------------------------------------------------------------
# Capture session — orchestrates a single capture run in a background thread
# ---------------------------------------------------------------------------

class CaptureSession:
    def __init__(self, capture_id, interface, simulate, duration, max_packets, out_dir):
        self.id = capture_id
        self.interface = interface
        self.simulate = simulate
        self.duration = duration
        self.max_packets = max_packets
        self.status = "idle"       # idle | capturing | done | error
        self.packets_captured = 0
        self.error = None
        self.csv_path = None
        self.started_at = None
        self.finished_at = None
        self.out_dir = out_dir
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._sniffer = None  # scapy AsyncSniffer, set once real capture starts

    def to_dict(self):
        with self._lock:
            return {
                "capture_id": self.id,
                "interface": self.interface,
                "simulate": self.simulate,
                "status": self.status,
                "packets_captured": self.packets_captured,
                "error": self.error,
                "csv_filename": os.path.basename(self.csv_path) if self.csv_path else None,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
            }

    def request_stop(self):
        """Ask a running capture to stop early. Whatever was captured so far
        still gets written to CSV — this is not an abort, just an early finish."""
        self._stop_event.set()
        with self._lock:
            sniffer = self._sniffer
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass

    def run(self):
        with self._lock:
            self.status = "capturing"
            self.started_at = time.time()

        try:
            if not self.simulate:
                ok, msg = check_monitor_mode(self.interface)
                if not ok:
                    with self._lock:
                        self.status = "error"
                        self.error = msg
                        self.finished_at = time.time()
                    return

            os.makedirs(self.out_dir, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S", time.localtime(self.started_at))
            self.csv_path = os.path.join(self.out_dir, f"capture_{ts}.csv")

            rows = []
            if self.simulate:
                t0 = time.time()
                prev_time = None
                i = 0
                if self.duration is not None and self.max_packets:
                    interval = min(0.05, self.duration / max(self.max_packets, 1))
                else:
                    interval = 0.05
                while True:
                    if self._stop_event.is_set():
                        break
                    if self.max_packets is not None and i >= self.max_packets:
                        break
                    if self.duration is not None and (time.time() - t0) >= self.duration:
                        break
                    i += 1
                    row = generate_mock_row(i, t0, prev_time)
                    prev_time = row["frame.time_epoch"]
                    rows.append(row)
                    with self._lock:
                        self.packets_captured = i
                    time.sleep(interval)
            else:
                from scapy.all import AsyncSniffer

                state = {"prev_time": None, "count": 0}

                def handler(pkt):
                    state["count"] += 1
                    row = extract_fields(pkt, state["count"], self.started_at, state["prev_time"])
                    state["prev_time"] = row["frame.time_epoch"]
                    rows.append(row)
                    with self._lock:
                        self.packets_captured = state["count"]

                sniffer = AsyncSniffer(
                    iface=self.interface,
                    prn=handler,
                    timeout=self.duration,                                   # None = no time limit
                    count=self.max_packets if self.max_packets is not None else 0,  # 0 = no count limit (scapy)
                    store=False,
                )
                with self._lock:
                    self._sniffer = sniffer
                sniffer.start()
                sniffer.join()

            with open(self.csv_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=FIELD_ORDER)
                writer.writeheader()
                for row in rows:
                    writer.writerow(row)

            with self._lock:
                self.status = "done"
                self.finished_at = time.time()

        except PermissionError:
            with self._lock:
                self.status = "error"
                self.error = "Permission denied opening the capture interface — run the app with sudo / CAP_NET_RAW."
                self.finished_at = time.time()
        except OSError as e:
            with self._lock:
                self.status = "error"
                self.error = f"Capture failed: {e}"
                self.finished_at = time.time()
        except Exception as e:
            with self._lock:
                self.status = "error"
                self.error = f"Unexpected error: {e}"
                self.finished_at = time.time()


def start_capture(interface, simulate, duration, max_packets, out_dir):
    capture_id = str(uuid.uuid4())
    session = CaptureSession(capture_id, interface, simulate, duration, max_packets, out_dir)
    thread = threading.Thread(target=session.run, daemon=True)
    thread.start()
    return session
