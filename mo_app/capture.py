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
    "frame.time_relative", "frame.time_delta_displayed",
    # wlan / radiotap (blocked on non-monitor-mode hardware — see params_coverage_report.md)
    "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.retry", "wlan.fc.protected",
    "wlan.duration", "wlan.seq", "wlan.ssid", "wlan.da",
    "radiotap.channel.freq", "radiotap.datarate", "wlan_radio.signal_dbm",
    # arp
    "arp.opcode", "arp.hw.type", "arp.proto.type", "arp.hw.size", "arp.proto.size",
    # eapol
    "eapol.type", "eapol.len", "eapol.keydes.key_len",
    # ip
    "ip.version",
    # tcp
    "tcp.flags.ack", "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.reset",
    "tcp.flags.push", "tcp.analysis.retransmission",
    # dns
    "dns.flags.response", "dns.count.queries", "dns.count.answers",
    "dns.count.auth_rr", "dns.count.add_rr", "dns.flags.authoritative",
    "dns.flags.checkdisable", "dns.flags.opcode", "dns.count.labels",
    # http
    "http.request.method", "http.response.code",
    "http.content_length", "http.connection", "http.request.version", "http.response.version",
    # dhcp
    "dhcp.id", "dhcp.cookie", "dhcp.option.router",
    "dhcp.option.dhcp_server_id", "dhcp.option.broadcast_address",
    # smb2 (generic 64-byte header fields only — see report for what's excluded)
    "smb2.protocol_id", "smb2.header_len", "smb2.cmd", "smb2.pid",
    # nbss (legacy NetBIOS Session Service, port 139)
    "nbss.length", "nbss.type",
    # tls (cleartext handshake only)
    "tls.handshake.version",
    # engineered indicator columns
    "has_app_features", "has_mac_features",
    # presence-only flags for protocols with no single named raw field in the spec
    "dhcp.present", "smb.present", "smb2.present", "ssh.present",
    "tls.present", "mdns.present", "nbss.present", "icmpv6.present",
    "ldap.present", "nbns.present", "ssdp.present", "llc.present",
]

MISSING = -1

# Columns considered "app/transport-layer" for the has_app_features indicator
# (mirrors params.md's has_app_features: true if any non-MAC-layer field was
# actually observed on this packet).
_APP_FEATURE_COLS = [
    "arp.opcode", "arp.hw.type", "arp.proto.type", "arp.hw.size", "arp.proto.size",
    "eapol.type", "eapol.len", "eapol.keydes.key_len", "ip.version",
    "tcp.flags.ack", "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.reset", "tcp.flags.push",
    "tcp.analysis.retransmission",
    "dns.flags.response", "dns.count.queries", "dns.count.answers", "dns.count.auth_rr",
    "dns.count.add_rr", "dns.flags.authoritative", "dns.flags.checkdisable",
    "dns.flags.opcode", "dns.count.labels",
    "http.request.method", "http.response.code", "http.content_length", "http.connection",
    "http.request.version", "http.response.version",
    "dhcp.id", "dhcp.cookie", "dhcp.option.router", "dhcp.option.dhcp_server_id",
    "dhcp.option.broadcast_address",
    "smb2.protocol_id", "smb2.header_len", "smb2.cmd", "smb2.pid",
    "nbss.length", "nbss.type", "tls.handshake.version",
    "dhcp.present", "smb.present", "smb2.present", "ssh.present", "tls.present",
    "mdns.present", "nbss.present", "icmpv6.present", "ldap.present", "nbns.present",
    "ssdp.present", "llc.present",
]

# Columns considered "MAC/PHY-layer" for the has_mac_features indicator. These
# all require monitor mode to ever be non-MISSING (see report).
_MAC_FEATURE_COLS = [
    "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.retry", "wlan.fc.protected",
    "wlan.duration", "wlan.seq", "wlan.ssid", "wlan.da",
    "radiotap.channel.freq", "radiotap.datarate", "wlan_radio.signal_dbm",
]

PORT_PRESENCE = {
    "dhcp.present": (67, 68),
    "smb.present": (445,),
    "smb2.present": (445,),
    "ssh.present": (22,),
    "tls.present": (443,),
    "mdns.present": (5353,),
    "nbss.present": (139,),
    "ldap.present": (389,),
    "nbns.present": (137,),
    "ssdp.present": (1900,),
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


def extract_fields(pkt, frame_number, first_time, prev_time, session_state=None):
    """Extract the raw fields listed in FIELD_ORDER from a scapy packet.

    session_state (optional dict) carries cross-packet state needed for a
    couple of fields (currently just TCP retransmission detection) — pass the
    same dict on every call within one capture session so it can accumulate.
    """
    from scapy.all import Dot11, RadioTap, Dot11Elt, ARP, IP, TCP, DNS

    if session_state is None:
        session_state = {}
    seen_tcp_seqs = session_state.setdefault("seen_tcp_seqs", set())

    row = {k: MISSING for k in FIELD_ORDER}

    t = float(pkt.time) if getattr(pkt, "time", None) is not None else MISSING
    row["frame.number"] = frame_number
    row["frame.time_epoch"] = t
    try:
        row["frame.len"] = len(bytes(pkt))
    except Exception:
        row["frame.len"] = MISSING
    row["frame.time_delta"] = (t - prev_time) if (prev_time is not None and t != MISSING) else 0.0
    # Wireshark's frame.time_relative is time since the FIRST captured frame;
    # first_time here is session start (close approximation, not byte-identical).
    row["frame.time_relative"] = (t - first_time) if (t != MISSING and first_time is not None) else MISSING
    # No display-filter reordering happens in a live capture, so "displayed"
    # delta is identical to the raw delta.
    row["frame.time_delta_displayed"] = row["frame.time_delta"]

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
        row["arp.hw.size"] = _get(a, "hwlen")
        row["arp.proto.size"] = _get(a, "plen")

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

        # Retransmission heuristic: same (src,sport,dst,dport,seq,payload-len)
        # observed twice in this capture session. Not Wireshark-equivalent —
        # real tshark tracks full stream state (SACK, out-of-order, ACK'd
        # ranges); this only catches exact duplicate segments.
        try:
            ip_ = pkt[IP] if pkt.haslayer(IP) else None
            key = (
                _get(ip_, "src", None) if ip_ else None,
                _get(t_, "sport", None),
                _get(ip_, "dst", None) if ip_ else None,
                _get(t_, "dport", None),
                _get(t_, "seq", None),
                len(bytes(t_.payload)) if t_.payload else 0,
            )
            if None not in key[:4]:
                if key in seen_tcp_seqs:
                    row["tcp.analysis.retransmission"] = 1
                else:
                    row["tcp.analysis.retransmission"] = 0
                    seen_tcp_seqs.add(key)
        except Exception:
            row["tcp.analysis.retransmission"] = MISSING

    if pkt.haslayer(DNS):
        dns_ = pkt[DNS]
        row["dns.flags.response"] = _get(dns_, "qr")
        row["dns.count.queries"] = _get(dns_, "qdcount")
        row["dns.count.answers"] = _get(dns_, "ancount")
        row["dns.count.auth_rr"] = _get(dns_, "nscount")
        row["dns.count.add_rr"] = _get(dns_, "arcount")
        row["dns.flags.authoritative"] = _get(dns_, "aa")
        row["dns.flags.checkdisable"] = _get(dns_, "cd")
        row["dns.flags.opcode"] = _get(dns_, "opcode")
        try:
            qd = dns_.qd
            if qd is not None:
                qname = _get(qd, "qname", b"")
                if isinstance(qname, bytes):
                    qname = qname.decode(errors="replace")
                row["dns.count.labels"] = qname.rstrip(".").count(".") + 1 if qname else MISSING
        except Exception:
            pass

    try:
        from scapy.layers.http import HTTPRequest, HTTPResponse
        if pkt.haslayer(HTTPRequest):
            hreq = pkt[HTTPRequest]
            m = _get(hreq, "Method", None)
            row["http.request.method"] = m.decode() if isinstance(m, bytes) else (m or MISSING)
            v = _get(hreq, "Http_Version", None)
            row["http.request.version"] = v.decode() if isinstance(v, bytes) else (v or MISSING)
            cl = _get(hreq, "Content_Length", None)
            row["http.content_length"] = cl.decode() if isinstance(cl, bytes) else (cl if cl is not None else MISSING)
            conn = _get(hreq, "Connection", None)
            row["http.connection"] = conn.decode() if isinstance(conn, bytes) else (conn or MISSING)
        if pkt.haslayer(HTTPResponse):
            hresp = pkt[HTTPResponse]
            c = _get(hresp, "Status_Code", None)
            row["http.response.code"] = c.decode() if isinstance(c, bytes) else (c or MISSING)
            v = _get(hresp, "Http_Version", None)
            row["http.response.version"] = v.decode() if isinstance(v, bytes) else (v or MISSING)
            cl = _get(hresp, "Content_Length", None)
            row["http.content_length"] = cl.decode() if isinstance(cl, bytes) else (cl if cl is not None else MISSING)
            conn = _get(hresp, "Connection", None)
            row["http.connection"] = conn.decode() if isinstance(conn, bytes) else (conn or MISSING)
    except ImportError:
        pass

    # DHCP — scapy exposes options as a list of (name, value) tuples on BOOTP
    try:
        from scapy.all import DHCP, BOOTP
        if pkt.haslayer(DHCP):
            bootp = pkt[BOOTP] if pkt.haslayer(BOOTP) else None
            if bootp is not None:
                row["dhcp.id"] = _get(bootp, "xid")
            row["dhcp.cookie"] = "99.130.83.99"  # RFC-fixed magic cookie (0x63825363), constant
            opts = {}
            for opt in _get(pkt[DHCP], "options", []) or []:
                if isinstance(opt, tuple) and len(opt) >= 2:
                    opts[opt[0]] = opt[1]
            if "server_id" in opts:
                row["dhcp.option.dhcp_server_id"] = opts["server_id"]
            if "router" in opts:
                r = opts["router"]
                row["dhcp.option.router"] = r[0] if isinstance(r, (list, tuple)) else r
            if "broadcast_address" in opts:
                row["dhcp.option.broadcast_address"] = opts["broadcast_address"]
    except ImportError:
        pass
    except Exception:
        pass

    # SMB2 — only the fixed 64-byte generic header (present on every SMB2
    # message, cleartext even under SMB3 encryption). Command-specific body
    # fields (buffer_code, session_flags, write_length, data_offset,
    # auth_frame) are NOT parsed here — see report.
    try:
        if pkt.haslayer(TCP) and (_get(t_, "sport") == 445 or _get(t_, "dport") == 445):
            raw = bytes(t_.payload)
            # Direct SMB-over-TCP framing: 4-byte length-prefix header, then SMB2 header
            offset = 4 if len(raw) >= 4 and raw[0] == 0 else 0
            if len(raw) >= offset + 16 and raw[offset:offset + 4] == b"\xfeSMB":
                row["smb2.protocol_id"] = "0xfe534d42"
                row["smb2.header_len"] = int.from_bytes(raw[offset + 4:offset + 6], "little")
                row["smb2.cmd"] = int.from_bytes(raw[offset + 12:offset + 14], "little")
                row["smb2.pid"] = int.from_bytes(raw[offset + 32:offset + 36], "little")
    except Exception:
        pass

    # NBSS — legacy NetBIOS Session Service framing on port 139 (4-byte header:
    # 1 byte type, 3 byte length)
    try:
        if pkt.haslayer(TCP) and (_get(t_, "sport") == 139 or _get(t_, "dport") == 139):
            raw = bytes(t_.payload)
            if len(raw) >= 4:
                row["nbss.type"] = raw[0]
                row["nbss.length"] = int.from_bytes(raw[1:4], "big")
    except Exception:
        pass

    # TLS — only the cleartext handshake version field from a ClientHello/
    # ServerHello record header (works before encryption starts; nothing after
    # the handshake is readable). Other tls.* fields (alerts, session tickets,
    # compressed-cert extension, connection ID) need full record/extension
    # parsing and are not implemented — see report.
    try:
        if pkt.haslayer(TCP) and (_get(t_, "sport") == 443 or _get(t_, "dport") == 443):
            raw = bytes(t_.payload)
            if len(raw) >= 11 and raw[0] == 0x16 and raw[5] in (1, 2):
                version = (raw[9] << 8) | raw[10]
                row["tls.handshake.version"] = f"0x{version:04x}"
    except Exception:
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

    # LLC — 802.2 Logical Link Control (rarely seen on a WiFi client's own
    # managed-mode interface; the OS normally hands userspace only Ethernet-II
    # framed IP traffic, not raw 802.3/LLC frames). Included for completeness.
    try:
        from scapy.all import LLC
        if pkt.haslayer(LLC):
            row["llc.present"] = 1
    except Exception:
        pass

    # Engineered indicator columns (computed from the columns above, matching
    # params.md's definition: 1 if the row actually has any field from that
    # OSI-layer group, before the -1 missingness sentinel).
    row["has_app_features"] = 1 if any(row.get(c, MISSING) != MISSING for c in _APP_FEATURE_COLS) else 0
    row["has_mac_features"] = 1 if any(row.get(c, MISSING) != MISSING for c in _MAC_FEATURE_COLS) else 0

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
    row["frame.time_relative"] = t - t0
    row["frame.time_delta_displayed"] = row["frame.time_delta"]
    row["frame.encap_type"] = 127

    kind = random.choices(
        ["beacon", "data", "arp", "tcp", "dns", "dhcp", "smb2", "http"],
        weights=[3, 3, 1, 2, 1, 1, 1, 1],
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
        row["arp.hw.size"] = 6
        row["arp.proto.size"] = 4
    if kind == "tcp":
        row["ip.version"] = 4
        row["tcp.flags.ack"] = random.choice([0, 1])
        row["tcp.flags.syn"] = random.choice([0, 1])
        row["tcp.flags.fin"] = 0
        row["tcp.flags.reset"] = 0
        row["tcp.flags.push"] = random.choice([0, 1])
        row["tcp.analysis.retransmission"] = 1 if random.random() < 0.05 else 0
        if random.random() < 0.15:
            row["tls.present"] = 1
            row["tls.handshake.version"] = random.choice(["0x0303", "0x0301"])
    if kind == "http":
        row["ip.version"] = 4
        row["tcp.flags.ack"] = 1
        row["tcp.analysis.retransmission"] = 0
        row["http.request.method"] = random.choice(["GET", "POST"])
        row["http.request.version"] = "HTTP/1.1"
        row["http.connection"] = "keep-alive"
        if random.random() < 0.5:
            row["http.response.code"] = random.choice([200, 404])
            row["http.response.version"] = "HTTP/1.1"
            row["http.content_length"] = random.choice([0, 512, 1024, 4096])
    if kind == "dns":
        row["ip.version"] = 4
        row["dns.flags.response"] = random.choice([0, 1])
        row["dns.count.queries"] = 1
        row["dns.count.answers"] = random.choice([0, 1, 2])
        row["dns.count.auth_rr"] = 0
        row["dns.count.add_rr"] = random.choice([0, 1])
        row["dns.flags.authoritative"] = 0
        row["dns.flags.checkdisable"] = 0
        row["dns.flags.opcode"] = 0
        row["dns.count.labels"] = random.choice([2, 3, 4])
    if kind == "dhcp":
        row["ip.version"] = 4
        row["dhcp.present"] = 1
        row["dhcp.id"] = f"0x{random.randint(0, 0xffffffff):08x}"
        row["dhcp.cookie"] = "99.130.83.99"
        row["dhcp.option.router"] = "192.168.2.1"
        row["dhcp.option.dhcp_server_id"] = "192.168.2.1"
        row["dhcp.option.broadcast_address"] = "192.168.2.255"
    if kind == "smb2":
        row["ip.version"] = 4
        row["smb2.present"] = 1
        row["smb2.protocol_id"] = "0xfe534d42"
        row["smb2.header_len"] = 64
        row["smb2.cmd"] = random.choice([0, 1, 3, 5, 8])
        row["smb2.pid"] = random.choice([0, 65279])

    row["has_app_features"] = 1 if any(
        row.get(c, MISSING) != MISSING for c in _APP_FEATURE_COLS
    ) else 0
    row["has_mac_features"] = 1 if any(
        row.get(c, MISSING) != MISSING for c in _MAC_FEATURE_COLS
    ) else 0

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

                state = {"prev_time": None, "count": 0, "seen_tcp_seqs": set()}

                def handler(pkt):
                    state["count"] += 1
                    row = extract_fields(pkt, state["count"], self.started_at, state["prev_time"], state)
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
