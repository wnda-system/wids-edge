"""Per-second window features for WiFi anomaly detection — shared by the
offline evaluator (anomaly_detect.py) and the live monitor (../monitor.py).
See ../anomaly_detection_notes.md for why each feature exists.
"""
import io
import os
import zlib
import numpy as np
import pandas as pd

USECOLS = ["frame.time_epoch", "frame.len", "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.retry",
           "wlan.fc.protected", "wlan_radio.signal_dbm", "wlan.ssid", "wlan.da", "wlan.sa",
           "wlan.ta", "wlan.bssid", "arp.opcode", "dhcp.present", "mdns.present", "ssdp.present",
           "ip.version", "tcp.flags.syn", "tls.present",
           "wlan.ra", "wlan.fixed.timestamp", "radiotap.mactime",
           "arp.src.hw_mac", "arp.src.proto_ipv4", "wlan.seq"]

HINTS = {
    "deauth": "Deauthentication attack", "disassoc": "Disassociation attack",
    "beacon": "Beacon flood", "n_ssid": "Beacon flood (many SSIDs)",
    "n_bssid": "Beacon flood / rogue APs", "max_bssid_per_ssid": "Evil twin (extra AP for an existing SSID)",
    "new_bssid_known_ssid": "Evil twin (unknown BSSID using a known SSID)",
    "probe_req": "Probe flood / scanning", "auth": "Authentication flood",
    "assoc_req": "Association flood", "rts": "RTS flood (jamming)", "cts": "CTS flood (jamming)",
    "retry_ratio": "Interference / jamming", "signal_std": "Spoofed transmitter (signal changed)",
    "arp": "ARP flood", "arp_reply_ratio": "ARP spoofing", "dhcp": "DHCP flood / rogue DHCP",
    "mdns": "mDNS flood", "ssdp": "SSDP flood / amplification", "n_sa": "Many new transmitters (MAC flood/spoof)",
    "frames": "Traffic volume spike (flood)",
    "deauth_to_one_client_10s": "Targeted deauth/disassoc (one client kicked repeatedly)",
    "tsf_offset_switches": "Evil twin with cloned BSSID (two clocks behind one BSSID)",
    "bssid_signal_range": "Evil twin with cloned BSSID (two locations behind one BSSID)",
    "bssid_beacon_rate": "Evil twin with cloned BSSID (extra beacons for one BSSID)",
    "arp_ip_mac_flips_10s": "ARP spoofing (one IP answered by alternating MACs)",
    "arp_ips_per_mac_60s": "ARP spoofing (one MAC claiming many IPs)",
    "deauth_seq_out_of_order": "Spoofed deauth/disassoc (sequence number doesn't fit the AP's own counter)",
}


# Features that describe traffic in general rather than one attack pattern.
# Rule B still flags them when they exceed anything seen in the baseline, but
# as an "info" notice: a phone held next to the sensor or a big download
# looks exactly like this.
GENERIC = {
    "signal_mean": "Unusually strong/weak average signal (a device very close to the sensor?)",
    "len_mean": "Unusually large frames on average (bulk transfer?)",
    "mgmt": "Unusually many management frames",
    "ctrl": "Unusually many control frames",
    "data": "Unusually many data frames",
    "protected_ratio": "Unusual share of encrypted frames",
    "n_dest_mac": "Unusually many destination addresses",
    "tcp": "Unusually many TCP SYNs",
}

# Bump whenever windows() changes what a feature means: the live monitor then
# recomputes its stored per-second table from the raw captures it kept.
#   2: per-client deauth count ignores frames proven to be the AP's own (seq);
#      late retries tolerated by the seq check (2026-10-09)
FEATURE_VERSION = 2

_NUMERIC = ["frame.time_epoch", "frame.len", "wlan.fc.type", "wlan.fc.subtype", "wlan.fc.retry",
            "wlan.fc.protected", "wlan_radio.signal_dbm", "arp.opcode",
            "wlan.fixed.timestamp", "radiotap.mactime", "wlan.seq"]


def clean(df, source):
    """Normalise capture rows (from a CSV or straight from extract_fields())
    into the typed frame windows() expects: -1 -> NaN, numeric columns cast."""
    df = df.reindex(columns=USECOLS)
    df = df.replace({-1: np.nan, "-1": np.nan})
    df[_NUMERIC] = df[_NUMERIC].apply(pd.to_numeric, errors="coerce")
    df["file"] = source
    return df


def load(path):
    try:
        df = pd.read_csv(path, usecols=lambda c: c in USECOLS, low_memory=False)
    except (EOFError, zlib.error, pd.errors.ParserError):
        # last chunk of a run cut off by a crash / power loss: keep every
        # complete line that made it to disk
        raw = open(path, "rb").read()
        if path.endswith(".gz"):
            raw = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(raw)
        text = raw.replace(b"\x00", b"").decode("utf-8", "ignore")
        df = pd.read_csv(io.StringIO(text[:text.rfind("\n") + 1]), usecols=lambda c: c in USECOLS,
                         low_memory=False)
    return clean(df, os.path.basename(path))


def windows(df, win, known_pairs=None, arp_seed=None):
    t, st = df["wlan.fc.type"], df["wlan.fc.subtype"]
    df = df.assign(
        _row=np.arange(len(df)),
        win=(df["frame.time_epoch"] // win).astype("int64"),
        _mgmt=(t == 0), _ctrl=(t == 1), _data=(t == 2),
        _beacon=(t == 0) & (st == 8), _probe_req=(t == 0) & (st == 4),
        _auth=(t == 0) & (st == 11), _assoc_req=(t == 0) & (st == 0),
        _deauth=(t == 0) & (st == 12), _disassoc=(t == 0) & (st == 10),
        _rts=(t == 1) & (st == 11), _cts=(t == 1) & (st == 12),
        _arp=df["arp.opcode"].notna(), _arp_reply=df["arp.opcode"] == 2,
        _dhcp=df["dhcp.present"].astype(str).isin(["1", "1.0"]),
        _mdns=df["mdns.present"].astype(str).isin(["1", "1.0"]),
        _ssdp=df["ssdp.present"].astype(str).isin(["1", "1.0"]),
        _tcp=df["tcp.flags.syn"].notna(),
    )
    # A deauth the client doesn't ACK is retransmitted (retry bit, same seq) up
    # to ~7 times — count each frame once, or a single AP-side deauth looks like
    # a burst (seen for real at 14:41:41: 87 frames, 26 unique).
    kick_mask = df["_deauth"] | df["_disassoc"]
    dup = kick_mask & df.duplicated(subset=["win", "wlan.ta", "wlan.ra", "wlan.seq", "wlan.fc.subtype"])
    df = df.assign(_deauth_u=df["_deauth"] & ~dup, _disassoc_u=df["_disassoc"] & ~dup)
    # n_dest_mac counts receiver addresses (addr1): wlan.ra, or wlan.da in files
    # older than wlan.ra. Field captures (raw schema 3) put the real DA in
    # wlan.da, so it can't be used directly without changing this feature.
    df = df.assign(_dest=df["wlan.ra"].fillna(df["wlan.da"]))
    g = df.groupby("win")
    s = lambda c: g[c].sum()
    f = pd.DataFrame({
        "frames": g.size(), "mgmt": s("_mgmt"), "ctrl": s("_ctrl"), "data": s("_data"),
        "beacon": s("_beacon"), "probe_req": s("_probe_req"), "auth": s("_auth"),
        "assoc_req": s("_assoc_req"), "deauth": s("_deauth_u"), "disassoc": s("_disassoc_u"),
        "rts": s("_rts"), "cts": s("_cts"),
        "retry_ratio": g["wlan.fc.retry"].mean(), "protected_ratio": g["wlan.fc.protected"].mean(),
        "signal_mean": g["wlan_radio.signal_dbm"].mean(), "signal_std": g["wlan_radio.signal_dbm"].std(),
        "len_mean": g["frame.len"].mean(),
        "n_ssid": g["wlan.ssid"].nunique(), "n_bssid": g["wlan.bssid"].nunique(),
        "n_sa": g["wlan.sa"].nunique(), "n_dest_mac": g["_dest"].nunique(),
        "arp": s("_arp"), "dhcp": s("_dhcp"), "mdns": s("_mdns"), "ssdp": s("_ssdp"), "tcp": s("_tcp"),
    })
    f["arp_reply_ratio"] = s("_arp_reply") / f["arp"].replace(0, np.nan)

    # Evil-twin features, from beacons only: how many BSSIDs advertise each SSID,
    # and whether a (SSID, BSSID) pair was never seen during training.
    b = df[df["_beacon"] & df["wlan.ssid"].notna() & df["wlan.bssid"].notna()]
    per = b.groupby(["win", "wlan.ssid"])["wlan.bssid"].nunique()
    f["max_bssid_per_ssid"] = per.groupby(level=0).max()
    pairs = set(zip(b["wlan.ssid"], b["wlan.bssid"]))
    if known_pairs is not None:
        known_ssids = {s for s, _ in known_pairs}
        new = b[[(s in known_ssids and (s, x) not in known_pairs)
                 for s, x in zip(b["wlan.ssid"], b["wlan.bssid"])]]
        f["new_bssid_known_ssid"] = new.groupby("win")["wlan.bssid"].nunique()
    else:
        f["new_bssid_known_ssid"] = 0

    # --- Spoofed deauth/disassoc. An AP uses ONE sequence counter for every
    # management frame it sends, so a genuine deauth's seq sits between the
    # seq of that AP's previous and next beacon (true for all 33 real ones in
    # the 1.5 h baseline; the gap is ~13-111 of 4096). A frame forged with the
    # AP's address but the attacker's own counter lands outside that gap.
    bcn_seq = df[df["_beacon"]][["frame.time_epoch", "wlan.ta", "wlan.seq"]].dropna().sort_values("frame.time_epoch")
    k = df[(df["_deauth_u"] | df["_disassoc_u"]) & df["wlan.ta"].isin(bcn_seq["wlan.ta"].unique())]
    k = k[["_row", "frame.time_epoch", "win", "wlan.ta", "wlan.seq", "wlan.fc.retry"]].dropna().sort_values("frame.time_epoch")
    f["deauth_seq_out_of_order"] = 0
    verified = set()
    if len(k):
        prv = pd.merge_asof(k, bcn_seq.rename(columns={"wlan.seq": "p", "frame.time_epoch": "tp"}),
                            left_on="frame.time_epoch", right_on="tp", by="wlan.ta", direction="backward")
        nxt = pd.merge_asof(k, bcn_seq.rename(columns={"wlan.seq": "n", "frame.time_epoch": "tn"}),
                            left_on="frame.time_epoch", right_on="tn", by="wlan.ta", direction="forward")
        prv["n"] = nxt["n"].to_numpy()
        judged = prv.dropna(subset=["p", "n"])
        out = (judged["wlan.seq"] - judged["p"]) % 4096 > (judged["n"] - judged["p"]) % 4096
        # A retransmission (retry bit) of a deauth sent just before the previous
        # beacon carries that older, slightly lower seq — seen live: seq 1720
        # retried after beacon 1723 when the original wasn't captured. Allow a
        # small backlog for retries; a forged random seq still lands outside.
        late_retry = (judged["wlan.fc.retry"] == 1) & ((judged["p"] - judged["wlan.seq"]) % 4096 <= 64)
        out &= ~late_retry
        f["deauth_seq_out_of_order"] = judged[out].groupby("win").size().reindex(f.index)
        verified = set(judged.loc[~out, "_row"])

    # --- per-BSSID beacon consistency (cloned-BSSID evil twin).
    # offset = AP's TSF clock - our adapter's clock. A real AP's offset is
    # rock-steady (≤14 µs jitter in the baseline); a second device using the
    # same BSSID has its own clock, so consecutive beacons flip between two
    # offsets. Count flips (|Δoffset| > 1 ms) per BSSID per window — a real AP
    # re-syncing its clock is one flip, a clone is a flip on most beacons.
    bb = df[df["_beacon"] & df["wlan.bssid"].notna()].copy()
    bb["off"] = bb["wlan.fixed.timestamp"] - bb["radiotap.mactime"]
    bb["flip"] = (bb.groupby("wlan.bssid")["off"].diff().abs() > 1000).astype(int)
    gb = bb.groupby(["win", "wlan.bssid"])
    f["tsf_offset_switches"] = gb["flip"].sum().groupby(level=0).max()
    f["bssid_signal_range"] = (gb["wlan_radio.signal_dbm"].max() - gb["wlan_radio.signal_dbm"].min()).groupby(level=0).max()
    f["bssid_beacon_rate"] = gb.size().groupby(level=0).max()

    # --- per-client: deauth/disassoc aimed at the same receiver, trailing 10 s.
    # Normal leaves are rare and one-off; an attacker repeats them at one victim.
    # Frames whose seq proves they came from the AP itself (above) don't count:
    # an AP repeatedly kicking a confused client (reason 7, "class 3 frame from
    # non-associated STA") is normal here — 253 of them at one phone in 20 min
    # on 2026-10-08, every one in the AP's own sequence.
    kick = df[(df["_deauth_u"] | df["_disassoc_u"]) & ~df["_row"].isin(verified)][["win", "wlan.ra"]].dropna()
    if len(kick):
        per_ra = kick.groupby(["wlan.ra", "win"]).size().rename("n").reset_index()
        rows = []
        for ra, g_ra in per_ra.groupby("wlan.ra"):
            ser = g_ra.set_index("win")["n"]
            full = ser.reindex(range(ser.index.min(), ser.index.max() + 10), fill_value=0)
            rows.append(full.rolling(10, min_periods=1).sum())
        f["deauth_to_one_client_10s"] = pd.concat(rows, axis=1).max(axis=1).reindex(f.index)
    else:
        f["deauth_to_one_client_10s"] = 0

    # --- ARP spoofing. An IP that legitimately moves to a new device changes
    # MAC once; while a spoofer is active, the real owner keeps answering too,
    # so the IP's MAC flips back and forth. Count flips per IP over 10 s.
    # Also: an attacker MAC typically claims the victim/gateway IP on top of
    # its own, so count distinct IPs claimed per sender MAC over 60 s.
    arp = df[df["_arp"]][["win", "arp.src.hw_mac", "arp.src.proto_ipv4"]].dropna()
    arp = arp[(arp["arp.src.proto_ipv4"] != "0.0.0.0") & (arp["arp.src.hw_mac"] != "00:00:00:00:00:00")]
    if arp_seed is not None and len(arp) and len(arp_seed):
        # last IP->MAC binding learned in training, placed just before this
        # data, so the very first spoofed reply already counts as a change
        seed = arp_seed.assign(win=arp["win"].min() - 1)
        arp = pd.concat([seed, arp], ignore_index=True)
    f["arp_ip_mac_flips_10s"] = 0
    f["arp_ips_per_mac_60s"] = 0
    if len(arp):
        prev = arp.groupby("arp.src.proto_ipv4")["arp.src.hw_mac"].shift()
        arp = arp.assign(flip=(prev.notna() & (prev != arp["arp.src.hw_mac"])).astype(int))
        flips = arp.groupby(["arp.src.proto_ipv4", "win"])["flip"].sum()
        f["arp_ip_mac_flips_10s"] = _trailing_max(flips, 10).reindex(f.index)
        ips = []
        for mac, g_mac in arp.groupby("arp.src.hw_mac"):
            wins = g_mac["win"].to_numpy()
            ipv = g_mac["arp.src.proto_ipv4"].to_numpy()
            out = {}
            for w in np.unique(wins):
                out[w] = len(set(ipv[(wins > w - 60) & (wins <= w)]))
            ips.append(pd.Series(out))
        f["arp_ips_per_mac_60s"] = pd.concat(ips, axis=1).max(axis=1).reindex(f.index)

    f["file"] = g["file"].first()
    return f.fillna(0), pairs


def _trailing_max(counts, span):
    """counts: Series indexed by (entity, win). For each window, the max over
    entities of that entity's event count in the trailing `span` windows."""
    rows = []
    for _, g_e in counts.groupby(level=0):
        ser = g_e.droplevel(0)
        full = ser.reindex(range(ser.index.min(), ser.index.max() + span), fill_value=0)
        rows.append(full.rolling(span, min_periods=1).sum())
    return pd.concat(rows, axis=1).max(axis=1)
