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
import math
import os
import random
import shutil
import subprocess
import threading
import time
import uuid

# scapy.layers.http patches TCP's payload dissection to recognize HTTP
# request/response bodies as a side effect of being imported — that patch
# only applies to packets dissected *after* the import runs. Importing it
# here at module load time (before any capture starts) instead of lazily
# inside extract_fields() avoids a cold-start gap where the very first
# packet of a session, if it happened to be HTTP, would dissect as opaque
# Raw and never be recognized (harmless for real capture ordering — TCP/DNS/
# etc. packets almost always arrive before the first HTTP request/response
# in practice — but wrong when a synthetic-packet test or the HTTP
# correlation logic assumes detection works on packet #1).
try:
    from scapy.layers.http import HTTPRequest, HTTPResponse  # noqa: F401
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Column schema (order is the CSV column order)
# ---------------------------------------------------------------------------

FIELD_ORDER = [
    # frame
    "frame.number", "frame.time_epoch", "frame.len", "frame.time_delta", "frame.encap_type",
    "frame.time_relative", "frame.time_delta_displayed",
    # wlan / radiotap (needs monitor mode — see params_coverage_report.md)
    "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.retry", "wlan.fc.protected",
    "wlan.fc.frag", "wlan.fc.order", "wlan.fc.moredata", "wlan.fc.pwrmgt", "wlan.fc.ds",
    "wlan.duration", "wlan.seq", "wlan.ssid", "wlan.da",
    "radiotap.channel.freq", "radiotap.datarate", "radiotap.length", "radiotap.mactime",
    "radiotap.channel.flags.cck", "radiotap.channel.flags.ofdm",
    "radiotap.present.tsft", "radiotap.timestamp.ts",
    "wlan_radio.signal_dbm", "wlan_radio.frequency", "wlan_radio.data_rate", "wlan_radio.channel",
    # wlan_radio.duration/end_tsf are computed from a published IEEE 802.11
    # TXTIME formula (legacy DSSS/CCK + OFDM PHY modes only — see
    # _legacy_txtime_us()'s docstring). MISSING for HT/VHT/HE rates or any
    # rate this formula doesn't recognize, rather than guessing.
    "wlan_radio.timestamp", "wlan_radio.start_tsf", "wlan_radio.duration", "wlan_radio.end_tsf",
    # wlan fixed-parameters — only present on the specific management-frame
    # subtypes that carry them (beacon/probe-response for timestamp/interval/
    # capabilities, deauth/disassoc for reason_code); MISSING elsewhere, same
    # as every other conditionally-present field in this schema.
    "wlan.fixed.timestamp", "wlan.fixed.beacon", "wlan.fixed.capabilities.ess",
    "wlan.fixed.capabilities.ibss", "wlan.fixed.reason_code",
    # wlan.tag: a frame can carry many information elements, each with its
    # own tag number — this column can't be a single scalar the way most
    # fields here are. Following tshark's own convention for a repeating
    # field exported to one CSV column, this is every tag ID seen in the
    # frame, comma-joined in order (e.g. "0,1,50,221"), not just the first.
    "wlan.tag",
    # wlan.rsn.capabilities.mfpc: bit 0x0080 of the RSN element's (tag 48)
    # Capabilities field, reached by walking past its variable-length
    # cipher-suite and AKM-suite lists first.
    "wlan.rsn.capabilities.mfpc",
    # arp (description is derived from opcode + a transient sender/target IP
    # comparison — the IPs themselves are never stored as a column, only used
    # in-memory to classify the frame, consistent with the project's rule
    # against capturing identifier columns)
    "arp.opcode", "arp.hw.type", "arp.proto.type", "arp.hw.size", "arp.proto.size",
    "arp.description",
    # eapol
    "eapol.type", "eapol.len", "eapol.keydes.key_len", "eapol.keydes.replay_counter",
    # ip
    "ip.version",
    # tcp (checksum.status is a "Good"/"Bad" string from actually recomputing
    # the checksum and comparing — not a guess at Wireshark's internal
    # numeric enum, which I couldn't pin down with confidence)
    "tcp.flags.ack", "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.reset",
    "tcp.flags.push", "tcp.analysis.retransmission", "tcp.checksum.status",
    # dns (retransmit_request/retransmit_response/time are cross-packet, filled
    # in during capture via session_state transaction-ID tracking)
    "dns.flags.response", "dns.count.queries", "dns.count.answers",
    "dns.count.auth_rr", "dns.count.add_rr", "dns.flags.authoritative",
    "dns.flags.checkdisable", "dns.flags.opcode", "dns.count.labels", "dns.resp.len",
    "dns.retransmit_request", "dns.retransmit_response", "dns.time",
    # dns.description / mdns.description: the human-readable "Domain Name
    # System (query)"/"(response)" summary string, trivially derived from
    # dns.flags.response — same DNS wire format for both, mDNS just gated
    # on port 5353 instead of 53.
    "dns.description", "mdns.description",
    # http (request_in/response_in/time are cross-packet, filled in during
    # capture via session_state per-stream FIFO matching; next_request_in/
    # next_response_in — HTTP pipelining collision fields — are NOT
    # implemented, low-confidence semantics for the effort. request.method/
    # response.code/response.code.desc are also filled in for SSDP — see
    # the SSDP block further down for why that's an "http" field, not a
    # separate ssdp one.)
    "http.request.method", "http.response.code", "http.response.code.desc",
    "http.content_length", "http.connection", "http.request.version", "http.response.version",
    "http.request_in", "http.response_in", "http.time",
    # dhcp (description is the "Dynamic Host Configuration Protocol (ACK)"-
    # style summary string, from the message-type option via scapy's own
    # DHCPTypes name table)
    "dhcp.id", "dhcp.cookie", "dhcp.option.router",
    "dhcp.option.dhcp_server_id", "dhcp.option.broadcast_address", "dhcp.hw.addr_padding",
    "dhcp.description",
    # ssh — cleartext version banner + KEXINIT/KEX-DH-GEX-request/KEXDH-reply
    # fields, hand-parsed (scapy has no SSH dissector). Single-packet only,
    # like the other hand-rolled parsers below — a KEXINIT split across TCP
    # segments won't be parsed. Encrypted post-NEWKEYS traffic is opaque.
    "ssh.protocol", "ssh.direction", "ssh.message_code", "ssh.packet_length",
    "ssh.padding_length", "ssh.padding_string", "ssh.cookie",
    "ssh.kex_algorithms_length", "ssh.server_host_key_algorithms_length",
    "ssh.encryption_algorithms_client_to_server_length",
    "ssh.encryption_algorithms_server_to_client_length",
    "ssh.mac_algorithms_client_to_server_length",
    "ssh.mac_algorithms_server_to_client_length",
    "ssh.compression_algorithms_client_to_server_length",
    "ssh.compression_algorithms_server_to_client_length",
    "ssh.dh_gex.min", "ssh.dh_gex.max", "ssh.dh_gex.nbits",
    "ssh.host_key.length", "ssh.host_key.type_length", "ssh.mpint_length",
    # smb2 (64-byte generic header, plus command-body fields for the two
    # commands cheap to hand-parse at fixed offsets: WRITE request and
    # SESSION_SETUP response. auth_frame needs session-wide correlation —
    # not implemented.)
    "smb2.protocol_id", "smb2.header_len", "smb2.cmd", "smb2.pid",
    "smb2.buffer_code", "smb2.session_flags", "smb2.write_length", "smb2.data_offset",
    # smb (v1) — fixed-offset header fields, plus 3 well-documented Flags/
    # Flags2 bits (MS-CIFS 2.2.3.1: 0x80 in Flags = REPLY, 0x0004 in Flags2
    # = SECURITY_SIGNATURE, 0x4000 in Flags2 = NT_STATUS), plus the 3
    # GENERIC_* ACCESS_MASK bits (MS-DTYP 2.4.3) — but only out of an
    # NT_CREATE_ANDX (cmd 0xA2) *request* body, at that command's own fixed
    # DesiredAccess offset, gated on WordCount==24 as a sanity check before
    # trusting the offset. smb.flags.notify is still not implemented — I
    # couldn't pin down its exact bit position/semantics with confidence,
    # and getting a bit-flag field subtly wrong is worse than -1.
    "smb.mid", "smb.tid", "smb.pid.high", "smb.nt_status", "smb.server_component",
    "smb.flags.response", "smb.flags2.sec_sig", "smb.flags2.nt_error",
    "smb.access.generic_read", "smb.access.generic_write", "smb.access.generic_execute",
    # nbss (legacy NetBIOS Session Service, port 139)
    "nbss.length", "nbss.type",
    # tls (cleartext handshake only, plus alert record and ClientHello
    # session_ticket extension. connection_id / compressed-certificate need a
    # fuller extension walk — not implemented.)
    "tls.handshake.version", "tls.alert_message.level", "tls.alert_message.desc",
    "tls.handshake.session_ticket_length",
    # icmpv6 — scapy has a proper MLDv2 Report dissector (ICMPv6MLReport2)
    # with this field modeled directly, so no hand-parsing needed. Only
    # present on MLDv2 Report messages (ICMPv6 type 143).
    "icmpv6.mldr.nb_mcast_records",
    # engineered indicator columns
    "has_app_features", "has_mac_features",
    # n_unique_dest_mac_per_sec — behavioral feature, filled in as a
    # post-processing pass over the whole capture (see _add_derived_columns);
    # needs monitor mode (depends on wlan.da) same as the wlan.*/radiotap.*
    # block below.
    "n_unique_dest_mac_per_sec",
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
    "arp.description",
    "eapol.type", "eapol.len", "eapol.keydes.key_len", "eapol.keydes.replay_counter", "ip.version",
    "tcp.flags.ack", "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.reset", "tcp.flags.push",
    "tcp.analysis.retransmission", "tcp.checksum.status",
    "dns.flags.response", "dns.count.queries", "dns.count.answers", "dns.count.auth_rr",
    "dns.count.add_rr", "dns.flags.authoritative", "dns.flags.checkdisable",
    "dns.flags.opcode", "dns.count.labels", "dns.resp.len", "dns.retransmit_request",
    "dns.retransmit_response", "dns.time", "dns.description", "mdns.description",
    "http.request.method", "http.response.code", "http.response.code.desc", "http.content_length", "http.connection",
    "http.request.version", "http.response.version", "http.request_in", "http.response_in",
    "http.time",
    "dhcp.id", "dhcp.cookie", "dhcp.option.router", "dhcp.option.dhcp_server_id",
    "dhcp.option.broadcast_address", "dhcp.hw.addr_padding", "dhcp.description",
    "icmpv6.mldr.nb_mcast_records",
    "ssh.protocol", "ssh.direction", "ssh.message_code", "ssh.packet_length",
    "ssh.padding_length", "ssh.padding_string", "ssh.cookie",
    "ssh.kex_algorithms_length", "ssh.server_host_key_algorithms_length",
    "ssh.encryption_algorithms_client_to_server_length",
    "ssh.encryption_algorithms_server_to_client_length",
    "ssh.mac_algorithms_client_to_server_length", "ssh.mac_algorithms_server_to_client_length",
    "ssh.compression_algorithms_client_to_server_length",
    "ssh.compression_algorithms_server_to_client_length",
    "ssh.dh_gex.min", "ssh.dh_gex.max", "ssh.dh_gex.nbits",
    "ssh.host_key.length", "ssh.host_key.type_length", "ssh.mpint_length",
    "smb2.protocol_id", "smb2.header_len", "smb2.cmd", "smb2.pid",
    "smb2.buffer_code", "smb2.session_flags", "smb2.write_length", "smb2.data_offset",
    "smb.mid", "smb.tid", "smb.pid.high", "smb.nt_status", "smb.server_component",
    "smb.flags.response", "smb.flags2.sec_sig", "smb.flags2.nt_error",
    "smb.access.generic_read", "smb.access.generic_write", "smb.access.generic_execute",
    "nbss.length", "nbss.type", "tls.handshake.version", "tls.alert_message.level",
    "tls.alert_message.desc", "tls.handshake.session_ticket_length",
    "dhcp.present", "smb.present", "smb2.present", "ssh.present", "tls.present",
    "mdns.present", "nbss.present", "icmpv6.present", "ldap.present", "nbns.present",
    "ssdp.present", "llc.present",
]

# Columns considered "MAC/PHY-layer" for the has_mac_features indicator. These
# all require monitor mode to ever be non-MISSING (see report).
_MAC_FEATURE_COLS = [
    "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.retry", "wlan.fc.protected",
    "wlan.fc.frag", "wlan.fc.order", "wlan.fc.moredata", "wlan.fc.pwrmgt", "wlan.fc.ds",
    "wlan.duration", "wlan.seq", "wlan.ssid", "wlan.da",
    "radiotap.channel.freq", "radiotap.datarate", "radiotap.length", "radiotap.mactime",
    "radiotap.channel.flags.cck", "radiotap.channel.flags.ofdm",
    "radiotap.present.tsft", "radiotap.timestamp.ts",
    "wlan_radio.signal_dbm", "wlan_radio.frequency", "wlan_radio.data_rate", "wlan_radio.channel",
    "wlan_radio.timestamp", "wlan_radio.start_tsf", "wlan_radio.duration", "wlan_radio.end_tsf",
    "wlan.fixed.timestamp", "wlan.fixed.beacon", "wlan.fixed.capabilities.ess",
    "wlan.fixed.capabilities.ibss", "wlan.fixed.reason_code",
    "wlan.tag", "wlan.rsn.capabilities.mfpc",
    "n_unique_dest_mac_per_sec",
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


def _freq_to_channel(freq_mhz):
    """Standard WiFi frequency (MHz) -> channel number mapping (2.4/5/6 GHz).
    Returns MISSING for anything outside the known bands rather than
    guessing."""
    try:
        freq_mhz = int(freq_mhz)
    except (TypeError, ValueError):
        return MISSING
    if freq_mhz == 2484:
        return 14
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2407) // 5
    if freq_mhz == 5935:
        return 2
    if 5955 <= freq_mhz <= 7115:  # 6 GHz (WiFi 6E)
        return (freq_mhz - 5950) // 5
    if 5000 <= freq_mhz <= 5895:  # 5 GHz
        return (freq_mhz - 5000) // 5
    return MISSING


_DSSS_RATES_MBPS = (1, 2, 5.5, 11)
_OFDM_RATES_MBPS = (6, 9, 12, 18, 24, 36, 48, 54)


def _legacy_txtime_us(rate_mbps, frame_len_bytes, short_preamble=False):
    """Best-effort PPDU airtime (Wireshark's wlan_radio.duration) in
    microseconds, using the published IEEE 802.11 TXTIME formula —
    **legacy (non-HT/VHT/HE) PHY modes only**:

      DSSS/CCK (802.11b, 1/2/5.5/11 Mbps): 192 us PLCP preamble+header
      (96 us if short preamble — not permitted at 1 Mbps), plus
      ceil(length_bits / rate) for the payload (Mbps == bits/us, so no
      unit conversion needed).

      OFDM (802.11a/g, 6-54 Mbps): 16 us training + 4 us SIGNAL symbol,
      plus ceil((16 service bits + 8*length + 6 tail bits) / (rate*4))
      OFDM symbols at 4 us each.

    HT/VHT/HE (802.11n/ac/ax MCS rates) use different, more involved
    formulas (MCS-dependent bits/symbol, spatial streams, guard interval) —
    deliberately not implemented here; returns MISSING for those and for
    any rate outside the recognized legacy set, rather than guessing.

    frame_len_bytes should be the actual over-the-air MPDU length (the
    802.11 header + body, roughly — not the radiotap-prefixed capture
    length); the caller is responsible for that distinction.
    """
    try:
        rate = float(rate_mbps)
        length = int(frame_len_bytes)
    except (TypeError, ValueError):
        return MISSING
    if rate in _DSSS_RATES_MBPS:
        overhead_us = 96 if (short_preamble and rate != 1) else 192
        payload_us = math.ceil((length * 8) / rate)
        return overhead_us + payload_us
    if rate in _OFDM_RATES_MBPS:
        n_dbps = rate * 4
        n_sym = math.ceil((16 + length * 8 + 6) / n_dbps)
        return 20 + n_sym * 4
    return MISSING


def _parse_rsn_mfpc(info):
    """Extract bit 0x0080 (MFPC — Management Frame Protection Capable) out
    of an RSN information element's (802.11 tag ID 48) RSN Capabilities
    field. That field sits after two variable-length suite lists, so this
    walks: version(2) + group_cipher(4) + pairwise_count(2) +
    pairwise_suites(4*n) + akm_count(2) + akm_suites(4*n) + capabilities(2).
    Returns MISSING if the element is shorter than expected."""
    try:
        if len(info) < 8:
            return MISSING
        off = 2 + 4  # version + group cipher suite
        pairwise_count = int.from_bytes(info[off:off + 2], "little")
        off += 2 + 4 * pairwise_count
        if len(info) < off + 2:
            return MISSING
        akm_count = int.from_bytes(info[off:off + 2], "little")
        off += 2 + 4 * akm_count
        if len(info) < off + 2:
            return MISSING
        capabilities = int.from_bytes(info[off:off + 2], "little")
        return 1 if (capabilities & 0x0080) else 0
    except Exception:
        return MISSING


# ---------------------------------------------------------------------------
# LLC/SNAP dispatch — opt-in, off by default (see extract_fields's
# llc_snap_dispatch parameter).
#
# What this closes: an unencrypted 802.11 Data frame carries its IP/ARP/
# EAPOL payload wrapped in an 802.2 LLC header, almost always with SNAP
# (RFC 1042) encapsulation. scapy *can* auto-dissect through that chain (an
# LLC/SNAP/IP packet built and re-parsed from wire bytes does come back with
# a working IP layer) — but relying on that alone means every app-layer
# extraction block downstream only ever sees whatever scapy's own dissector
# chain happened to walk into. This instead reads the MAC-header length and
# LLC/SNAP header explicitly off the raw bytes and re-dissects the payload
# by hand, so app-layer extraction doesn't depend on that chain resolving
# correctly for a given driver/capture path. Only ever applied to frames
# that are (a) type=Data and (b) not already showing a protected bit set —
# an encrypted payload is ciphertext, not LLC/SNAP, and parsing it as such
# would either produce garbage or (overwhelmingly likely) just fail the
# SNAP magic-byte check below and correctly no-op.
# ---------------------------------------------------------------------------

def _dot11_data_header_len(fc_type, fc_subtype, to_ds, from_ds, order_bit):
    """MAC header length (bytes) for an 802.11 Data frame. Returns None for
    non-Data frames, or when the length can't be determined with
    confidence — an HT Control field (Order bit set on a QoS frame adds 4
    more bytes) is deliberately left unhandled; bail rather than risk a
    wrong offset on a frame type this hasn't been checked against."""
    if fc_type != 2:
        return None
    is_qos = bool(fc_subtype & 0x08)
    if is_qos and order_bit:
        return None  # HT Control field present — offset uncertain, bail
    base = 30 if (to_ds and from_ds) else 24  # 4-address (WDS) vs 3-address
    if is_qos:
        base += 2  # QoS Control field
    return base


def _llc_snap_dispatch(raw, header_len):
    """If raw[header_len:] is a standard SNAP-encapsulated (RFC 1042) LLC
    frame — DSAP=SSAP=0xAA, Control=0x03, OUI=00:00:00 — decode the payload
    after the 8-byte LLC/SNAP header into the scapy class matching its
    EtherType (the SNAP header's last 2 bytes). Returns a freshly-dissected
    scapy packet, or None if this isn't SNAP-encapsulated, the EtherType
    isn't one of the ones this app parses further, or anything about the
    bytes doesn't line up with what's expected."""
    if header_len is None or len(raw) < header_len + 8:
        return None
    llc = raw[header_len:header_len + 8]
    dsap, ssap, control, oui = llc[0], llc[1], llc[2], llc[3:6]
    if not (dsap == 0xAA and ssap == 0xAA and control == 0x03 and oui == b"\x00\x00\x00"):
        return None  # not standard SNAP — don't guess at a meaning for these bytes
    ethertype = (llc[6] << 8) | llc[7]
    payload = raw[header_len + 8:]
    if not payload:
        return None
    try:
        if ethertype == 0x0800:
            from scapy.all import IP
            return IP(payload)
        if ethertype == 0x0806:
            from scapy.all import ARP
            return ARP(payload)
        if ethertype == 0x888E:
            from scapy.layers.eap import EAPOL
            return EAPOL(payload)
        if ethertype == 0x86DD:
            from scapy.all import IPv6
            return IPv6(payload)
    except Exception:
        return None
    return None  # unrecognized EtherType — nothing further to parse


# ---------------------------------------------------------------------------
# SSH — hand-rolled parser (scapy has no SSH dissector)
#
# Covers: the cleartext version-exchange banner, and — from the Binary Packet
# Protocol framing that follows it — SSH_MSG_KEXINIT (20), SSH_MSG_KEX_DH_GEX_
# REQUEST (34), and SSH_MSG_KEXDH_REPLY / SSH_MSG_KEX_DH_GEX_REPLY / SSH_MSG_
# KEX_ECDH_REPLY (all code 31; same leading K_S host-key-blob + second
# length-prefixed field shape, so one parser handles all three well enough
# for length/blob-size purposes). Everything after SSH_MSG_NEWKEYS is
# encrypted and unreadable — expected, not a bug.
#
# Single TCP segment only, same limitation as the SMB2/TLS/NBSS parsers
# below: no stream reassembly, so a KEXINIT that straddles two segments is
# silently skipped rather than partially/incorrectly parsed.
# ---------------------------------------------------------------------------

_SSH_KEXINIT_LENGTH_FIELDS = [
    "ssh.kex_algorithms_length",
    "ssh.server_host_key_algorithms_length",
    "ssh.encryption_algorithms_client_to_server_length",
    "ssh.encryption_algorithms_server_to_client_length",
    "ssh.mac_algorithms_client_to_server_length",
    "ssh.mac_algorithms_server_to_client_length",
    "ssh.compression_algorithms_client_to_server_length",
    "ssh.compression_algorithms_server_to_client_length",
    # languages_client_to_server / languages_server_to_client name-lists
    # follow but aren't in the training column set — parsed (to keep the
    # offset walk correct) and discarded.
]


def _parse_ssh_kexinit(body, out):
    if len(body) < 16:
        return
    out["ssh.cookie"] = body[:16].hex()
    off = 16
    for i in range(10):  # 8 lengths we keep + 2 language lists we skip
        if off + 4 > len(body):
            return
        length = int.from_bytes(body[off:off + 4], "big")
        off += 4
        if i < len(_SSH_KEXINIT_LENGTH_FIELDS):
            out[_SSH_KEXINIT_LENGTH_FIELDS[i]] = length
        off += length
        if off > len(body):
            return


def _parse_ssh_kexdh_reply(body, out):
    # string K_S (host key / certificate blob): 4-byte length + blob, whose
    # own first field is a 4-byte-length-prefixed key-type string.
    if len(body) < 4:
        return
    ks_len = int.from_bytes(body[0:4], "big")
    out["ssh.host_key.length"] = ks_len
    ks = body[4:4 + ks_len]
    if len(ks) >= 4:
        out["ssh.host_key.type_length"] = int.from_bytes(ks[0:4], "big")
    off = 4 + ks_len
    # Next length-prefixed field: mpint f (classic DH) or string Q_S
    # (ECDH) — both are 4-byte-length-prefixed, so the byte count is valid
    # either way even though only the DH case is a true mpint.
    if off + 4 <= len(body):
        out["ssh.mpint_length"] = int.from_bytes(body[off:off + 4], "big")


def parse_ssh(raw, sport, dport):
    """Best-effort single-packet SSH field extraction from a TCP payload."""
    out = {}
    out["ssh.direction"] = 1 if dport == 22 else (2 if sport == 22 else MISSING)

    if raw[:4] == b"SSH-":
        line = raw.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
        try:
            out["ssh.protocol"] = line.decode(errors="replace")
        except Exception:
            pass
        return out

    if len(raw) < 6:
        return out

    packet_length = int.from_bytes(raw[0:4], "big")
    padding_length = raw[4]
    if packet_length <= 0 or packet_length > len(raw) + 4:
        # Not a plausible BPP record in this single segment (could be a
        # continuation of a record started in an earlier segment) — bail
        # rather than guess.
        return out
    out["ssh.packet_length"] = packet_length
    out["ssh.padding_length"] = padding_length

    payload_len = packet_length - padding_length - 1
    if payload_len <= 0 or len(raw) < 5 + payload_len:
        return out
    payload = raw[5:5 + payload_len]

    pad_end = 5 + payload_len + padding_length
    if len(raw) >= pad_end:
        out["ssh.padding_string"] = raw[5 + payload_len:pad_end].hex()

    if not payload:
        return out
    msg_code = payload[0]
    out["ssh.message_code"] = msg_code
    body = payload[1:]

    if msg_code == 20:
        _parse_ssh_kexinit(body, out)
    elif msg_code == 34 and len(body) >= 12:
        out["ssh.dh_gex.min"] = int.from_bytes(body[0:4], "big")
        out["ssh.dh_gex.nbits"] = int.from_bytes(body[4:8], "big")
        out["ssh.dh_gex.max"] = int.from_bytes(body[8:12], "big")
    elif msg_code == 31:
        _parse_ssh_kexdh_reply(body, out)

    return out


def extract_fields(pkt, frame_number, first_time, prev_time, session_state=None,
                    llc_snap_dispatch=False):
    """Extract the raw fields listed in FIELD_ORDER from a scapy packet.

    session_state (optional dict) carries cross-packet state needed for a
    couple of fields (currently just TCP retransmission detection) — pass the
    same dict on every call within one capture session so it can accumulate.

    llc_snap_dispatch (default False — this is the "original" behavior):
    when True, an unencrypted 802.11 Data frame whose payload scapy didn't
    already dissect into IP/ARP/EAPOL gets a manual LLC/SNAP walk (see
    _llc_snap_dispatch()'s docstring) as a second attempt. All the
    "app-layer" extraction below (everything from ARP onward — TCP, DNS,
    HTTP, DHCP, SMB, SSH, TLS, ...) then runs against whichever succeeded.
    Opt-in rather than the default because it's new and not yet validated
    against a real capture; the wlan.*/radiotap.* MAC-layer fields above are
    unaffected either way.
    """
    from scapy.all import (
        Dot11, RadioTap, Dot11Elt, Dot11Beacon, Dot11ProbeResp, Dot11Deauth,
        Dot11Disas, ARP, IP, TCP, DNS, UDP,
    )

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
        fc_raw = _get(d11, "FCfield", None)
        # Bug fix: after a real wire dissection, scapy represents FCfield as
        # a FlagValue object, not a plain int (`isinstance(fc, int)` is
        # False for it) — the old isinstance guard here meant retry/
        # protected silently stayed -1 on every real captured packet, ever.
        # Only directly-constructed-in-Python Dot11 objects (like the ones
        # in this file's own unit tests before this fix) hit the `int` path.
        # int() works on both.
        try:
            fc = int(fc_raw)
        except (TypeError, ValueError):
            fc = None
        if fc is not None:
            # Bit positions per scapy's Dot11 FCfield layout (confirmed via
            # introspection: to_DS, from_DS, MF, retry, pw_mgt, MD,
            # protected, order — matches 802.11's standard Frame Control bit
            # order):
            row["wlan.fc.retry"] = 1 if (fc & 0x08) else 0
            row["wlan.fc.protected"] = 1 if (fc & 0x40) else 0
            row["wlan.fc.frag"] = 1 if (fc & 0x04) else 0       # More Fragments
            row["wlan.fc.pwrmgt"] = 1 if (fc & 0x10) else 0     # Power Management
            row["wlan.fc.moredata"] = 1 if (fc & 0x20) else 0   # More Data
            row["wlan.fc.order"] = 1 if (fc & 0x80) else 0
            # DS status: Wireshark packs to_DS (bit 0x01) and from_DS
            # (bit 0x02) — already adjacent low bits — into one 2-bit value
            # (0=not leaving/entering a DS, 1=to DS, 2=from DS, 3=DS-to-DS/WDS).
            row["wlan.fc.ds"] = fc & 0x03
        row["wlan.duration"] = _get(d11, "ID")
        sc = _get(d11, "SC", None)
        row["wlan.seq"] = (sc >> 4) if isinstance(sc, int) else MISSING
        row["wlan.da"] = _get(d11, "addr1")

        # Walk every information element once: SSID lives in tag ID=0
        # (typically beacon/probe frames), RSN lives in tag ID=48, and
        # wlan.tag itself is every tag ID seen, in order.
        elt = pkt.getlayer(Dot11Elt)
        tag_ids = []
        while elt is not None:
            tag_id = getattr(elt, "ID", None)
            if tag_id is not None:
                tag_ids.append(str(tag_id))
            if tag_id == 0 and row["wlan.ssid"] == MISSING:
                try:
                    row["wlan.ssid"] = elt.info.decode(errors="replace")
                except Exception:
                    pass
            elif tag_id == 48:
                mfpc = _parse_rsn_mfpc(bytes(elt.info))
                if mfpc != MISSING:
                    row["wlan.rsn.capabilities.mfpc"] = mfpc
            elt = elt.payload.getlayer(Dot11Elt)
        if tag_ids:
            row["wlan.tag"] = ",".join(tag_ids)

        # Fixed parameters — only present on the management-frame subtypes
        # that carry them.
        beacon_like = pkt.getlayer(Dot11Beacon) or pkt.getlayer(Dot11ProbeResp)
        if beacon_like is not None:
            row["wlan.fixed.timestamp"] = _get(beacon_like, "timestamp")
            row["wlan.fixed.beacon"] = _get(beacon_like, "beacon_interval")
            cap = _get(beacon_like, "cap", None)
            if cap is not None:
                try:
                    row["wlan.fixed.capabilities.ess"] = 1 if cap.ESS else 0
                    row["wlan.fixed.capabilities.ibss"] = 1 if cap.IBSS else 0
                except AttributeError:
                    pass
        deauth_or_disas = pkt.getlayer(Dot11Deauth) or pkt.getlayer(Dot11Disas)
        if deauth_or_disas is not None:
            row["wlan.fixed.reason_code"] = _get(deauth_or_disas, "reason")

    if has_radiotap:
        rt = pkt[RadioTap]
        freq = _get(rt, "ChannelFrequency", None)
        row["radiotap.channel.freq"] = freq if freq is not None else MISSING
        rate = _get(rt, "Rate", None)
        row["radiotap.datarate"] = rate if rate is not None else MISSING
        signal = _get(rt, "dBm_AntSignal", None)
        row["wlan_radio.signal_dbm"] = signal if signal is not None else MISSING
        row["radiotap.length"] = _get(rt, "len")
        mactime = _get(rt, "mac_timestamp", None)
        row["radiotap.mactime"] = mactime if mactime is not None else MISSING
        chflags = _get(rt, "ChannelFlags", None)
        if chflags is not None:
            try:
                row["radiotap.channel.flags.cck"] = 1 if chflags.CCK else 0
                row["radiotap.channel.flags.ofdm"] = 1 if chflags.OFDM else 0
            except AttributeError:
                pass
        present = _get(rt, "present", None)
        if present is not None:
            try:
                row["radiotap.present.tsft"] = 1 if present.TSFT else 0
            except AttributeError:
                pass
        # radiotap.timestamp.ts is the *newer* radiotap "Timestamp" field
        # (RFC-style presence flag "timestamp", distinct from the legacy
        # TSFT field above — most drivers only ever emit one or the other).
        newer_ts = _get(rt, "timestamp", None)
        row["radiotap.timestamp.ts"] = newer_ts if newer_ts is not None else MISSING

        # wlan_radio.* are Wireshark's names for effectively the same
        # values RadioTap already exposes under its own names — duplicated
        # here under the params.md field names rather than re-derived.
        if freq is not None:
            row["wlan_radio.frequency"] = freq
            row["wlan_radio.channel"] = _freq_to_channel(freq)
        if rate is not None:
            row["wlan_radio.data_rate"] = rate
        if mactime is not None:
            # start_tsf is literally "the TSFT value at frame arrival" —
            # same number as radiotap.mactime, Wireshark's wlan_radio name
            # for it. wlan_radio.timestamp is the same value again under
            # yet another Wireshark field name for the same underlying
            # radio-clock reading.
            row["wlan_radio.timestamp"] = mactime
            row["wlan_radio.start_tsf"] = mactime

        # wlan_radio.duration/end_tsf: see _legacy_txtime_us()'s docstring
        # for exactly what this does and doesn't cover. Uses the Dot11
        # layer's own byte length (not the radiotap-prefixed capture
        # length) plus an assumed 4-byte FCS trailer, since that's what's
        # actually on the air even though scapy doesn't capture it.
        if has_dot11 and rate is not None:
            try:
                mpdu_len = len(bytes(pkt[Dot11])) + 4
                short_preamble = False
                flags = _get(rt, "Flags", None)
                if flags is not None:
                    try:
                        short_preamble = bool(flags.ShortPreamble)
                    except AttributeError:
                        pass
                duration_us = _legacy_txtime_us(rate, mpdu_len, short_preamble)
                if duration_us != MISSING:
                    row["wlan_radio.duration"] = duration_us
                    if mactime is not None:
                        row["wlan_radio.end_tsf"] = mactime + duration_us
            except Exception:
                pass

    # LLC — 802.2 Logical Link Control. This has to run against the true
    # original packet, *before* any LLC/SNAP dispatch rebinding below — once
    # that rebind happens, "pkt" points at the decoded IP/ARP/EAPOL payload,
    # which correctly has no LLC layer of its own to find.
    try:
        from scapy.all import LLC
        if pkt.haslayer(LLC):
            row["llc.present"] = 1
    except Exception:
        pass

    # LLC/SNAP dispatch (opt-in — see extract_fields's llc_snap_dispatch
    # param docstring). Only attempted when scapy's own dissection didn't
    # already find IP/ARP/EAPOL, and never on an encrypted frame (protected
    # bit set — that payload is ciphertext, not LLC/SNAP). On success,
    # every app-layer block from here down operates on the decoded
    # sub-packet instead of the original captured frame.
    if (llc_snap_dispatch and has_dot11
            and row.get("wlan.fc.protected") != 1
            and not (pkt.haslayer(ARP) or pkt.haslayer(IP))):
        try:
            from scapy.layers.eap import EAPOL as _EAPOL
            already_eapol = pkt.haslayer(_EAPOL)
        except ImportError:
            already_eapol = False
        # fc can be None here (FCfield failed to parse as an int) even
        # though has_dot11 is True — to_DS/from_DS/order are then genuinely
        # unknown, so bail rather than guess at the header length.
        if not already_eapol and fc is not None:
            try:
                header_len = _dot11_data_header_len(
                    row.get("wlan.fc.type"), row.get("wlan.fc.subtype"),
                    bool(fc & 0x01), bool(fc & 0x02),
                    row.get("wlan.fc.order") == 1,
                )
                decoded = _llc_snap_dispatch(bytes(pkt[Dot11]), header_len)
                if decoded is not None:
                    pkt = decoded
            except Exception:
                pass

    if pkt.haslayer(ARP):
        a = pkt[ARP]
        row["arp.opcode"] = _get(a, "op")
        row["arp.hw.type"] = _get(a, "hwtype")
        row["arp.proto.type"] = _get(a, "ptype")
        row["arp.hw.size"] = _get(a, "hwlen")
        row["arp.proto.size"] = _get(a, "plen")
        # Wireshark's "ARP Probe"/"ARP Announcement"/"reply/gratuitous ARP"
        # distinction needs comparing sender vs. target protocol address —
        # psrc/pdst are used transiently right here to classify the frame
        # and never stored as a column, so this doesn't add an identifier
        # column despite needing the IPs to compute.
        op = _get(a, "op", None)
        psrc = _get(a, "psrc", None)
        pdst = _get(a, "pdst", None)
        if op == 1:  # request
            if psrc == "0.0.0.0":
                row["arp.description"] = "ARP Probe"
            elif psrc is not None and psrc == pdst:
                row["arp.description"] = "ARP Announcement"
            else:
                row["arp.description"] = "request"
        elif op == 2:  # reply
            row["arp.description"] = "reply/gratuitous ARP" if (psrc is not None and psrc == pdst) else "reply"

    try:
        from scapy.layers.eap import EAPOL
        if pkt.haslayer(EAPOL):
            e = pkt[EAPOL]
            row["eapol.type"] = _get(e, "type")
            row["eapol.len"] = _get(e, "len")
            # scapy's EAPOL class only models the generic 4-byte header
            # (version/type/len) — it has no key_length/replay_counter
            # attributes, so getattr-based extraction always silently
            # returned -1 here before. The EAPOL-Key body (type == 3) is
            # fixed-offset binary right after that header:
            #   descriptor_type(1) key_info(2) key_length(2)
            #   replay_counter(8) nonce(32) iv(16) rsc(8) key_id(8) mic(16) ...
            if _get(e, "type") == 3:
                body = bytes(e.payload)
                if len(body) >= 13:
                    row["eapol.keydes.key_len"] = int.from_bytes(body[3:5], "big")
                    row["eapol.keydes.replay_counter"] = int.from_bytes(body[5:13], "big")
    except ImportError:
        pass

    if pkt.haslayer(IP):
        row["ip.version"] = _get(pkt[IP], "version")
    else:
        # Bug fix: this only ever checked the IPv4 IP layer, so any IPv6
        # traffic in a real capture silently fell through to -1 even though
        # params.md's ip.version_6 bucket implies IPv6 was present in
        # training. scapy's IPv6 layer has no "version" attribute (it's not
        # a modeled field, always 6 on the wire) — set it directly.
        try:
            from scapy.all import IPv6
            if pkt.haslayer(IPv6):
                row["ip.version"] = 6
        except ImportError:
            pass

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

        # tcp.checksum.status — actually recompute the checksum (delete it,
        # rebuild the packet so scapy fills in a fresh one, re-parse to read
        # it back out) and compare to what was captured, rather than
        # guessing at Wireshark's internal numeric Good/Bad/Unverified enum
        # (which I couldn't pin down with confidence). This is a monitor-
        # mode capture of *other* stations' complete over-the-air frames,
        # not the local machine's own outgoing traffic — so the usual
        # NIC-checksum-offload caveat (checksum only filled in by hardware
        # at TX time, invalid in a local capture taken before that) mostly
        # doesn't apply here: what's captured is what was actually
        # transmitted, checksum included.
        try:
            original = _get(t_, "chksum", None)
            if original is not None:
                pkt_copy = pkt.copy()
                del pkt_copy[TCP].chksum
                rebuilt = bytes(pkt_copy)
                recomputed = pkt.__class__(rebuilt)[TCP].chksum
                row["tcp.checksum.status"] = "Good" if recomputed == original else "Bad"
        except Exception:
            pass

    if pkt.haslayer(DNS):
        dns_ = pkt[DNS]
        qr = _get(dns_, "qr", None)
        row["dns.flags.response"] = qr
        # dns.description / mdns.description — same "Domain Name System
        # (query/response)" wire format either way, mDNS is just the same
        # protocol on port 5353 instead of 53.
        if qr is not None and qr != MISSING:
            label = "Domain Name System (response)" if qr else "Domain Name System (query)"
            is_mdns = False
            if pkt.haslayer(UDP):
                u = pkt[UDP]
                is_mdns = _get(u, "sport") == 5353 or _get(u, "dport") == 5353
            if is_mdns:
                row["mdns.description"] = label.replace("Domain Name System", "Multicast Domain Name System")
            else:
                row["dns.description"] = label
        row["dns.count.queries"] = _get(dns_, "qdcount")
        row["dns.count.answers"] = _get(dns_, "ancount")
        row["dns.count.auth_rr"] = _get(dns_, "nscount")
        row["dns.count.add_rr"] = _get(dns_, "arcount")
        row["dns.flags.authoritative"] = _get(dns_, "aa")
        row["dns.flags.checkdisable"] = _get(dns_, "cd")
        row["dns.flags.opcode"] = _get(dns_, "opcode")
        if _get(dns_, "qr", 0):
            try:
                row["dns.resp.len"] = len(bytes(dns_))
            except Exception:
                pass
        try:
            qd = dns_.qd
            if qd is not None:
                qname = _get(qd, "qname", b"")
                if isinstance(qname, bytes):
                    qname = qname.decode(errors="replace")
                row["dns.count.labels"] = qname.rstrip(".").count(".") + 1 if qname else MISSING
        except Exception:
            pass

        # Transaction-based correlation: retransmit detection + response
        # timing. Keyed on (dns.id, UDP 4-tuple normalized so a
        # request/response pair share one key regardless of direction).
        try:
            udp_ = pkt[UDP] if pkt.haslayer(UDP) else None
            dns_id = _get(dns_, "id", None)
            if dns_id is not None and udp_ is not None and pkt.haslayer(IP):
                ip_ = pkt[IP]
                stream_key = (
                    dns_id,
                    frozenset({
                        (_get(ip_, "src", None), _get(udp_, "sport", None)),
                        (_get(ip_, "dst", None), _get(udp_, "dport", None)),
                    }),
                )
                dns_seen_requests = session_state.setdefault("dns_seen_requests", set())
                dns_answered = session_state.setdefault("dns_answered", set())
                dns_pending = session_state.setdefault("dns_pending", {})
                is_response = bool(_get(dns_, "qr", 0))
                if not is_response:
                    row["dns.retransmit_request"] = 1 if stream_key in dns_seen_requests else 0
                    dns_seen_requests.add(stream_key)
                    dns_pending[stream_key] = t
                else:
                    row["dns.retransmit_response"] = 1 if stream_key in dns_answered else 0
                    dns_answered.add(stream_key)
                    req_time = dns_pending.get(stream_key)
                    if req_time is not None and t != MISSING:
                        row["dns.time"] = t - req_time
        except Exception:
            pass

    try:
        from scapy.layers.http import HTTPRequest, HTTPResponse

        # Per-TCP-stream FIFO of pending (unanswered) requests, keyed on the
        # 4-tuple normalized so both directions of one connection share a
        # key. request_in/response_in/time need this cross-packet state;
        # next_request_in/next_response_in (pipelining collisions) are not
        # implemented.
        http_streams = session_state.setdefault("http_streams", {})
        stream_key = None
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            ip_ = pkt[IP]
            stream_key = frozenset({
                (_get(ip_, "src", None), _get(t_, "sport", None)),
                (_get(ip_, "dst", None), _get(t_, "dport", None)),
            })

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
            if stream_key is not None:
                http_streams.setdefault(stream_key, []).append((frame_number, t, row))
        if pkt.haslayer(HTTPResponse):
            hresp = pkt[HTTPResponse]
            c = _get(hresp, "Status_Code", None)
            row["http.response.code"] = c.decode() if isinstance(c, bytes) else (c or MISSING)
            desc = _get(hresp, "Reason_Phrase", None)
            row["http.response.code.desc"] = desc.decode() if isinstance(desc, bytes) else (desc or MISSING)
            v = _get(hresp, "Http_Version", None)
            row["http.response.version"] = v.decode() if isinstance(v, bytes) else (v or MISSING)
            cl = _get(hresp, "Content_Length", None)
            row["http.content_length"] = cl.decode() if isinstance(cl, bytes) else (cl if cl is not None else MISSING)
            conn = _get(hresp, "Connection", None)
            row["http.connection"] = conn.decode() if isinstance(conn, bytes) else (conn or MISSING)
            if stream_key is not None:
                pending = http_streams.get(stream_key)
                if pending:
                    req_frame_num, req_time, req_row = pending.pop(0)
                    row["http.request_in"] = req_frame_num
                    req_row["http.response_in"] = frame_number
                    if req_time != MISSING and t != MISSING:
                        row["http.time"] = t - req_time
    except ImportError:
        pass

    # SSDP — UDP port 1900, HTTP-like text syntax (M-SEARCH/NOTIFY requests,
    # "HTTP/1.1 200 OK" responses), but scapy's HTTPRequest/HTTPResponse
    # dissection is TCP-only, so pkt.haslayer(HTTPRequest) above is always
    # False for this traffic — the M-SEARCH/NOTIFY/SUBSCRIBE/UNSUBSCRIBE
    # buckets in http.request.method would otherwise never get any raw data
    # at all. Hand-parsed here into the *same* http.* fields used for real
    # HTTP, matching how the training data's own field group is named
    # (there's no separate "ssdp.*" field for this in params.md — SSDP
    # shows up entirely under "http", consistent with Wireshark's own
    # heuristic HTTP dissector picking up SSDP's HTTP-like syntax over UDP).
    # ssdp.description itself needs no new field: params.md's own naming
    # (ssdp_ssdp, a single-column group) says every observed SSDP frame in
    # training got the same one description string, so the existing
    # ssdp.present flag is already a complete raw equivalent.
    _SSDP_METHODS = (b"M-SEARCH", b"NOTIFY", b"SUBSCRIBE", b"UNSUBSCRIBE")
    try:
        if pkt.haslayer(UDP) and (_get(pkt[UDP], "sport") == 1900 or _get(pkt[UDP], "dport") == 1900):
            raw = bytes(pkt[UDP].payload)
            first_line = raw.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
            if first_line.startswith(b"HTTP/"):
                parts = first_line.split(b" ", 2)
                if len(parts) >= 2:
                    version = parts[0].decode(errors="replace")
                    code = parts[1].decode(errors="replace")
                    row["http.response.version"] = version
                    row["http.response.code"] = code
                    if len(parts) == 3:
                        row["http.response.code.desc"] = parts[2].decode(errors="replace")
            else:
                for method in _SSDP_METHODS:
                    if first_line.startswith(method + b" "):
                        row["http.request.method"] = method.decode()
                        rest = first_line[len(method):].strip().split(b" ")
                        if len(rest) >= 2 and rest[-1].startswith(b"HTTP/"):
                            row["http.request.version"] = rest[-1].decode(errors="replace")
                        break
    except Exception:
        pass

    # DHCP — scapy exposes options as a list of (name, value) tuples on BOOTP
    try:
        from scapy.all import DHCP, BOOTP
        if pkt.haslayer(DHCP):
            bootp = pkt[BOOTP] if pkt.haslayer(BOOTP) else None
            if bootp is not None:
                row["dhcp.id"] = _get(bootp, "xid")
                # chaddr is a fixed 16-byte field; only the first hlen bytes
                # are the actual hardware address, the rest is zero padding.
                hlen = _get(bootp, "hlen", None)
                chaddr = _get(bootp, "chaddr", None)
                if isinstance(hlen, int) and isinstance(chaddr, (bytes, bytearray)) and 0 <= hlen <= len(chaddr):
                    row["dhcp.hw.addr_padding"] = bytes(chaddr[hlen:]).hex()
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
            if "message-type" in opts:
                from scapy.layers.dhcp import DHCPTypes
                type_name = DHCPTypes.get(opts["message-type"], None)
                if type_name is not None:
                    row["dhcp.description"] = f"Dynamic Host Configuration Protocol ({type_name.upper() if type_name in ('ack', 'nak') else type_name.capitalize()})"
    except ImportError:
        pass
    except Exception:
        pass

    # SMB2 — the fixed 64-byte generic header (present on every SMB2 message,
    # cleartext even under SMB3 encryption), plus command-body fields for the
    # two commands cheap to hand-parse at a fixed offset: WRITE request
    # (write_length, data_offset) and SESSION_SETUP response (session_flags).
    # buffer_code is the body's own StructureSize field, present for every
    # command regardless. auth_frame needs session-wide request/response
    # correlation by MessageId — not implemented.
    try:
        if pkt.haslayer(TCP) and (_get(t_, "sport") == 445 or _get(t_, "dport") == 445):
            raw = bytes(t_.payload)
            # Direct SMB-over-TCP framing: 4-byte length-prefix header, then SMB2 header
            offset = 4 if len(raw) >= 4 and raw[0] == 0 else 0
            if len(raw) >= offset + 16 and raw[offset:offset + 4] == b"\xfeSMB":
                row["smb2.protocol_id"] = "0xfe534d42"
                row["smb2.header_len"] = int.from_bytes(raw[offset + 4:offset + 6], "little")
                cmd = int.from_bytes(raw[offset + 12:offset + 14], "little")
                row["smb2.cmd"] = cmd
                row["smb2.pid"] = int.from_bytes(raw[offset + 32:offset + 36], "little")

                flags = int.from_bytes(raw[offset + 16:offset + 20], "little")
                is_response = bool(flags & 0x00000001)
                body_off = offset + 64
                if len(raw) >= body_off + 2:
                    row["smb2.buffer_code"] = int.from_bytes(raw[body_off:body_off + 2], "little")
                if cmd == 9 and not is_response and len(raw) >= body_off + 8:  # WRITE request
                    row["smb2.data_offset"] = int.from_bytes(raw[body_off + 2:body_off + 4], "little")
                    row["smb2.write_length"] = int.from_bytes(raw[body_off + 4:body_off + 8], "little")
                if cmd == 1 and is_response and len(raw) >= body_off + 4:  # SESSION_SETUP response
                    row["smb2.session_flags"] = int.from_bytes(raw[body_off + 2:body_off + 4], "little")
    except Exception:
        pass

    # SMB (v1) — the literal fixed-offset 32-byte header fields (MS-CIFS
    # 2.2.3.1), plus 3 well-documented Flags/Flags2 bits and the
    # access.generic_* ACCESS_MASK bits out of one specific command body
    # (NT_CREATE_ANDX request) — see FIELD_ORDER's comment for exactly
    # which bits and why smb.flags.notify is still skipped.
    try:
        if pkt.haslayer(TCP) and (_get(t_, "sport") in (445, 139) or _get(t_, "dport") in (445, 139)):
            raw = bytes(t_.payload)
            offset = 4 if len(raw) >= 4 and raw[0] == 0 else 0
            if len(raw) >= offset + 32 and raw[offset:offset + 4] == b"\xffSMB":
                row["smb.server_component"] = "0xff534d42"
                cmd = raw[offset + 4]
                row["smb.nt_status"] = int.from_bytes(raw[offset + 5:offset + 9], "little")
                flags = raw[offset + 9]
                is_response = bool(flags & 0x80)
                row["smb.flags.response"] = 1 if is_response else 0
                flags2 = int.from_bytes(raw[offset + 10:offset + 12], "little")
                row["smb.flags2.sec_sig"] = 1 if (flags2 & 0x0004) else 0
                row["smb.flags2.nt_error"] = 1 if (flags2 & 0x4000) else 0
                row["smb.pid.high"] = int.from_bytes(raw[offset + 12:offset + 14], "little")
                row["smb.tid"] = int.from_bytes(raw[offset + 24:offset + 26], "little")
                row["smb.mid"] = int.from_bytes(raw[offset + 30:offset + 32], "little")

                # access.generic_* — only out of an NT_CREATE_ANDX (0xA2)
                # *request* body, at its own fixed DesiredAccess offset.
                # WordCount==24 is this command's documented value; treating
                # a mismatch as "not this command's body shape" rather than
                # trusting the offset anyway is the safety net that makes
                # this worth doing (vs. the other SMB1 body fields skipped).
                if cmd == 0xA2 and not is_response:
                    body_off = offset + 32
                    if len(raw) >= body_off + 20 and raw[body_off] == 24:
                        desired_access = int.from_bytes(raw[body_off + 16:body_off + 20], "little")
                        row["smb.access.generic_read"] = 1 if (desired_access & 0x80000000) else 0
                        row["smb.access.generic_write"] = 1 if (desired_access & 0x40000000) else 0
                        row["smb.access.generic_execute"] = 1 if (desired_access & 0x20000000) else 0
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

    # TLS — cleartext handshake version from a ClientHello/ServerHello record
    # header (works before encryption starts; nothing after the handshake is
    # readable), the alert record (level/description — also cleartext, TLS
    # never encrypts alerts sent before the handshake completes), and the
    # session_ticket extension length out of a ClientHello's extension list.
    # connection_id and the compressed-certificate message need a fuller
    # extension/message walk than this pass covers — not implemented.
    try:
        if pkt.haslayer(TCP) and (_get(t_, "sport") == 443 or _get(t_, "dport") == 443):
            raw = bytes(t_.payload)
            if len(raw) >= 11 and raw[0] == 0x16 and raw[5] in (1, 2):
                version = (raw[9] << 8) | raw[10]
                row["tls.handshake.version"] = f"0x{version:04x}"
                if raw[5] == 1:  # ClientHello — walk to the extensions list
                    try:
                        off = 9 + 2 + 32  # client_version + random
                        sid_len = raw[off]
                        off += 1 + sid_len
                        cs_len = int.from_bytes(raw[off:off + 2], "big")
                        off += 2 + cs_len
                        comp_len = raw[off]
                        off += 1 + comp_len
                        if off + 2 <= len(raw):
                            ext_total = int.from_bytes(raw[off:off + 2], "big")
                            off += 2
                            ext_end = min(off + ext_total, len(raw))
                            while off + 4 <= ext_end:
                                ext_type = int.from_bytes(raw[off:off + 2], "big")
                                ext_len = int.from_bytes(raw[off + 2:off + 4], "big")
                                if ext_type == 35:  # session_ticket
                                    row["tls.handshake.session_ticket_length"] = ext_len
                                    break
                                off += 4 + ext_len
                    except Exception:
                        pass
            elif len(raw) >= 7 and raw[0] == 0x15:  # Alert record
                row["tls.alert_message.level"] = raw[5]
                row["tls.alert_message.desc"] = raw[6]
    except Exception:
        pass

    # SSH — see parse_ssh() docstring for scope/limitations.
    try:
        if pkt.haslayer(TCP) and (_get(t_, "sport") == 22 or _get(t_, "dport") == 22):
            raw = bytes(t_.payload)
            if raw:
                for k, v in parse_ssh(raw, _get(t_, "sport"), _get(t_, "dport")).items():
                    row[k] = v
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

    # icmpv6.mldr.nb_mcast_records — only on an MLDv2 Report (ICMPv6 type
    # 143). Scapy has a proper dissector for this one (ICMPv6MLReport2),
    # unlike most of the hand-parsed fields elsewhere in this file.
    try:
        from scapy.all import ICMPv6MLReport2
        if pkt.haslayer(ICMPv6MLReport2):
            n = _get(pkt[ICMPv6MLReport2], "records_number", None)
            if n is not None:
                row["icmpv6.mldr.nb_mcast_records"] = n
    except ImportError:
        pass

    # Engineered indicator columns (computed from the columns above, matching
    # params.md's definition: 1 if the row actually has any field from that
    # OSI-layer group, before the -1 missingness sentinel).
    row["has_app_features"] = 1 if any(row.get(c, MISSING) != MISSING for c in _APP_FEATURE_COLS) else 0
    row["has_mac_features"] = 1 if any(row.get(c, MISSING) != MISSING for c in _MAC_FEATURE_COLS) else 0

    return row


def add_derived_columns(rows):
    """Whole-capture post-processing pass — features that need to see every
    row before they can be computed, so they can't be filled in per-packet
    inside extract_fields()/generate_mock_row(). Currently just
    n_unique_dest_mac_per_sec: count of distinct wlan.da values seen in the
    same 1-second bucket (floor(frame.time_epoch)), assigned back to every
    row in that bucket — matches the definition in params.md, computed
    before wlan.da/frame.time_epoch are dropped from the trained feature set.
    Mutates rows in place; also returns them for convenience.
    """
    buckets = {}
    for row in rows:
        t = row.get("frame.time_epoch", MISSING)
        da = row.get("wlan.da", MISSING)
        if t == MISSING or da == MISSING:
            continue
        try:
            bucket = int(t)
        except (TypeError, ValueError):
            continue
        buckets.setdefault(bucket, set()).add(da)

    for row in rows:
        t = row.get("frame.time_epoch", MISSING)
        if t == MISSING:
            continue
        try:
            bucket = int(t)
        except (TypeError, ValueError):
            continue
        if bucket in buckets:
            row["n_unique_dest_mac_per_sec"] = len(buckets[bucket])

    return rows


# ---------------------------------------------------------------------------
# Simulated (mock) capture — no hardware required
# ---------------------------------------------------------------------------

_SSIDS = ["HomeNet", "ASUS", "CoffeeShop_Guest", "Office5G"]
_MACS = lambda: ":".join(f"{random.randint(0,255):02x}" for _ in range(6))


def generate_mock_row(frame_number, t0, prev_time, sim_state=None):
    """sim_state (optional dict) mirrors extract_fields()'s session_state —
    used to fake cross-packet correlation (HTTP request/response, DNS
    retransmits) the same way the real capture path does, so simulate mode
    is a faithful preview of what those columns look like."""
    if sim_state is None:
        sim_state = {}
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
        ["beacon", "data", "arp", "tcp", "dns", "dhcp", "smb2", "http", "ssh", "eapol", "deauth", "smb1",
         "mdns", "icmpv6mldr", "ssdp"],
        weights=[3, 3, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
    )[0]

    row["wlan.fc.type"] = 0 if kind in ("beacon", "deauth") else 2
    row["wlan.fc.subtype"] = 8 if kind == "beacon" else (12 if kind == "deauth" else 0)
    row["wlan.fc.retry"] = random.choice([0, 1])
    row["wlan.fc.protected"] = random.choice([0, 1])
    row["wlan.fc.frag"] = random.choice([0, 1])
    row["wlan.fc.order"] = random.choice([0, 1])
    row["wlan.fc.moredata"] = random.choice([0, 1])
    row["wlan.fc.pwrmgt"] = random.choice([0, 1])
    row["wlan.fc.ds"] = random.choice([0, 1, 2, 3])
    row["wlan.duration"] = random.randint(0, 400)
    row["wlan.seq"] = frame_number % 4096
    row["wlan.da"] = _MACS()
    freq = random.choice([2412, 2437, 2462, 5180])
    rate = random.choice([1, 6, 24, 54])
    row["radiotap.channel.freq"] = freq
    row["radiotap.datarate"] = rate
    row["radiotap.length"] = random.choice([18, 23, 36])
    mactime = random.randint(0, 2**32 - 1)
    row["radiotap.mactime"] = mactime
    row["radiotap.channel.flags.cck"] = 1 if freq < 5000 else 0
    row["radiotap.channel.flags.ofdm"] = 0 if freq < 5000 else 1
    row["radiotap.present.tsft"] = 1
    row["wlan_radio.signal_dbm"] = -random.randint(30, 90)
    row["wlan_radio.frequency"] = freq
    row["wlan_radio.data_rate"] = rate
    row["wlan_radio.channel"] = _freq_to_channel(freq)
    row["wlan_radio.timestamp"] = mactime
    row["wlan_radio.start_tsf"] = mactime
    duration_us = _legacy_txtime_us(rate, random.randint(60, 1500), short_preamble=False)
    if duration_us != MISSING:
        row["wlan_radio.duration"] = duration_us
        row["wlan_radio.end_tsf"] = mactime + duration_us

    if kind == "beacon":
        row["wlan.ssid"] = random.choice(_SSIDS)
        row["wlan.fixed.timestamp"] = random.randint(0, 2**32 - 1)
        row["wlan.fixed.beacon"] = 100
        row["wlan.fixed.capabilities.ess"] = 1
        row["wlan.fixed.capabilities.ibss"] = 0
        row["wlan.tag"] = "0,1,3,48,221" if random.random() < 0.8 else "0,1,3"
        row["wlan.rsn.capabilities.mfpc"] = random.choice([0, 1])
    if kind == "deauth":
        row["wlan.fixed.reason_code"] = random.choice([1, 2, 3, 7, 8])
    if kind == "arp":
        row["arp.opcode"] = random.choice([1, 2])
        row["arp.hw.type"] = 1
        row["arp.proto.type"] = 0x0800
        row["arp.hw.size"] = 6
        row["arp.proto.size"] = 4
        row["arp.description"] = random.choice(["request", "reply", "ARP Probe", "ARP Announcement", "reply/gratuitous ARP"])
    if kind == "smb1":
        row["smb.present"] = 1
        row["smb.server_component"] = "0xff534d42"
        row["smb.nt_status"] = random.choice([0, 0xC0000022])
        row["smb.pid.high"] = 0
        row["smb.tid"] = random.randint(1, 20)
        row["smb.mid"] = frame_number % 65536
        is_resp = random.choice([0, 1])
        row["smb.flags.response"] = is_resp
        row["smb.flags2.sec_sig"] = random.choice([0, 1])
        row["smb.flags2.nt_error"] = random.choice([0, 1])
        if not is_resp and random.random() < 0.3:
            row["smb.access.generic_read"] = random.choice([0, 1])
            row["smb.access.generic_write"] = random.choice([0, 1])
            row["smb.access.generic_execute"] = 0
    if kind == "tcp":
        row["ip.version"] = 4
        row["tcp.flags.ack"] = random.choice([0, 1])
        row["tcp.flags.syn"] = random.choice([0, 1])
        row["tcp.flags.fin"] = 0
        row["tcp.flags.reset"] = 0
        row["tcp.flags.push"] = random.choice([0, 1])
        row["tcp.analysis.retransmission"] = 1 if random.random() < 0.05 else 0
        row["tcp.checksum.status"] = "Bad" if random.random() < 0.02 else "Good"
        if random.random() < 0.15:
            row["tls.present"] = 1
            if random.random() < 0.1:
                row["tls.alert_message.level"] = random.choice([1, 2])
                row["tls.alert_message.desc"] = random.choice([0, 10, 40, 50])
            else:
                row["tls.handshake.version"] = random.choice(["0x0303", "0x0301"])
                row["tls.handshake.session_ticket_length"] = random.choice([0, 200, 234])
    if kind == "http":
        row["ip.version"] = 4
        row["tcp.flags.ack"] = 1
        row["tcp.analysis.retransmission"] = 0
        row["http.request.method"] = random.choice(["GET", "POST"])
        row["http.request.version"] = "HTTP/1.1"
        row["http.connection"] = "keep-alive"
        # Fake one request/response pair per "stream" (reusing frame_number %
        # 5 as a cheap stand-in stream id) so request_in/response_in/time
        # have something realistic to show.
        http_pending = sim_state.setdefault("http_pending", {})
        stream_id = frame_number % 5
        if random.random() < 0.5:
            http_pending[stream_id] = (frame_number, t, row)
        else:
            code = random.choice([200, 404])
            row["http.response.code"] = code
            row["http.response.code.desc"] = {200: "OK", 404: "Not Found"}[code]
            row["http.response.version"] = "HTTP/1.1"
            row["http.content_length"] = random.choice([0, 512, 1024, 4096])
            pending = http_pending.pop(stream_id, None)
            if pending is not None:
                req_frame, req_time, req_row = pending
                row["http.request_in"] = req_frame
                row["http.time"] = t - req_time
                req_row["http.response_in"] = frame_number
    if kind == "dns":
        row["ip.version"] = 4
        is_response = random.choice([0, 1])
        row["dns.flags.response"] = is_response
        row["dns.count.queries"] = 1
        row["dns.count.answers"] = random.choice([0, 1, 2])
        row["dns.count.auth_rr"] = 0
        row["dns.count.add_rr"] = random.choice([0, 1])
        row["dns.flags.authoritative"] = 0
        row["dns.flags.checkdisable"] = 0
        row["dns.flags.opcode"] = 0
        row["dns.count.labels"] = random.choice([2, 3, 4])
        if is_response:
            row["dns.resp.len"] = random.choice([64, 90, 128])
        row["dns.description"] = "Domain Name System (response)" if is_response else "Domain Name System (query)"
        dns_id = frame_number % 7
        dns_seen = sim_state.setdefault("dns_seen_requests", set())
        dns_pending = sim_state.setdefault("dns_pending", {})
        if not is_response:
            row["dns.retransmit_request"] = 1 if dns_id in dns_seen else 0
            dns_seen.add(dns_id)
            dns_pending[dns_id] = t
        else:
            row["dns.retransmit_response"] = 0
            req_time = dns_pending.get(dns_id)
            if req_time is not None:
                row["dns.time"] = t - req_time
    if kind == "dhcp":
        row["ip.version"] = 4
        row["dhcp.present"] = 1
        row["dhcp.id"] = f"0x{random.randint(0, 0xffffffff):08x}"
        row["dhcp.cookie"] = "99.130.83.99"
        row["dhcp.option.router"] = "192.168.2.1"
        row["dhcp.option.dhcp_server_id"] = "192.168.2.1"
        row["dhcp.option.broadcast_address"] = "192.168.2.255"
        row["dhcp.hw.addr_padding"] = "00" * 10  # 16-byte chaddr, 6-byte MAC → 10 bytes padding
        row["dhcp.description"] = f"Dynamic Host Configuration Protocol ({random.choice(['Discover', 'Offer', 'Request', 'ACK'])})"
    if kind == "mdns":
        row["ip.version"] = 4
        row["mdns.present"] = 1
        is_resp = random.choice([0, 1])
        row["dns.flags.response"] = is_resp
        row["mdns.description"] = "Multicast Domain Name System (response)" if is_resp else "Multicast Domain Name System (query)"
    if kind == "icmpv6mldr":
        row["ip.version"] = 6
        row["icmpv6.present"] = 1
        row["icmpv6.mldr.nb_mcast_records"] = random.randint(1, 4)
    if kind == "ssdp":
        row["ip.version"] = 4
        row["ssdp.present"] = 1
        if random.random() < 0.6:
            row["http.request.method"] = random.choice(["M-SEARCH", "NOTIFY"])
            row["http.request.version"] = "HTTP/1.1"
        else:
            row["http.response.code"] = 200
            row["http.response.code.desc"] = "OK"
            row["http.response.version"] = "HTTP/1.1"
    if kind == "smb2":
        row["ip.version"] = 4
        row["smb2.present"] = 1
        row["smb2.protocol_id"] = "0xfe534d42"
        row["smb2.header_len"] = 64
        cmd = random.choice([0, 1, 3, 5, 8, 9])
        row["smb2.cmd"] = cmd
        row["smb2.pid"] = random.choice([0, 65279])
        row["smb2.buffer_code"] = random.choice([9, 17, 25, 41, 65])
        if cmd == 9:
            row["smb2.data_offset"] = 112
            row["smb2.write_length"] = random.choice([512, 1024, 4096])
        if cmd == 1:
            row["smb2.session_flags"] = 0
    if kind == "ssh":
        row["ssh.present"] = 1
        row["ip.version"] = 4
        row["ssh.direction"] = random.choice([1, 2])
        if random.random() < 0.2:
            row["ssh.protocol"] = random.choice(
                ["SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1", "SSH-2.0-libssh2_1.8.0"]
            )
        else:
            row["ssh.message_code"] = random.choice([20, 21, 31, 34])
            row["ssh.packet_length"] = random.choice([1052, 276, 20, 12])
            row["ssh.padding_length"] = random.randint(4, 16)
            row["ssh.padding_string"] = "00" * row["ssh.padding_length"]
            if row["ssh.message_code"] == 20:
                row["ssh.cookie"] = "".join(f"{random.randint(0,255):02x}" for _ in range(16))
                row["ssh.kex_algorithms_length"] = random.choice([80, 116])
                row["ssh.server_host_key_algorithms_length"] = random.choice([15, 53])
                row["ssh.encryption_algorithms_client_to_server_length"] = random.choice([21, 108])
                row["ssh.encryption_algorithms_server_to_client_length"] = random.choice([21, 108])
                row["ssh.mac_algorithms_client_to_server_length"] = random.choice([26, 158])
                row["ssh.mac_algorithms_server_to_client_length"] = random.choice([26, 158])
                row["ssh.compression_algorithms_client_to_server_length"] = 9
                row["ssh.compression_algorithms_server_to_client_length"] = 9
            elif row["ssh.message_code"] == 34:
                row["ssh.dh_gex.min"] = 1024
                row["ssh.dh_gex.nbits"] = 2048
                row["ssh.dh_gex.max"] = 8192
            elif row["ssh.message_code"] == 31:
                row["ssh.host_key.length"] = random.choice([279, 523])
                row["ssh.host_key.type_length"] = 11
                row["ssh.mpint_length"] = random.choice([256, 257])
    if kind == "eapol":
        row["eapol.type"] = 3
        row["eapol.len"] = random.choice([95, 117, 121])
        row["eapol.keydes.key_len"] = 16
        row["eapol.keydes.replay_counter"] = frame_number

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
    def __init__(self, capture_id, interface, simulate, duration, max_packets, out_dir,
                 llc_snap_dispatch=False):
        self.id = capture_id
        self.interface = interface
        self.simulate = simulate
        self.duration = duration
        self.max_packets = max_packets
        self.llc_snap_dispatch = llc_snap_dispatch
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
                "llc_snap_dispatch": self.llc_snap_dispatch,
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
                sim_state = {}
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
                    row = generate_mock_row(i, t0, prev_time, sim_state)
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
                    row = extract_fields(pkt, state["count"], self.started_at, state["prev_time"], state,
                                          llc_snap_dispatch=self.llc_snap_dispatch)
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

            add_derived_columns(rows)

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


def start_capture(interface, simulate, duration, max_packets, out_dir, llc_snap_dispatch=False):
    capture_id = str(uuid.uuid4())
    session = CaptureSession(capture_id, interface, simulate, duration, max_packets, out_dir,
                              llc_snap_dispatch=llc_snap_dispatch)
    thread = threading.Thread(target=session.run, daemon=True)
    thread.start()
    return session
