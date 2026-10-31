"""Unsupervised WiFi anomaly detection (see ../anomaly_detection_notes.md).

Needs pandas + scikit-learn (not in the app's venv): pip install pandas scikit-learn


1. Load every capture CSV in a directory (only the columns we need — RAM)
2. Aggregate frames into time windows -> one feature row per window
3. Split by TIME: earlier files = train, later files = held-out test
   (so the false-alarm rate is measured on data the detectors never saw)
4. Detector A: IsolationForest (multi-feature combinations)
   Detector B: per-feature robust z-score vs. the worst seen in training
   (catches features that were always 0 in training, which A is blind to)
5. Explain alerts by deviating features -> likely attack type
6. Inject synthetic attack windows to check each attack type is caught

Usage: python anomaly_detect.py <dir_with_csv_or_csv.gz> [window_seconds] [train_fraction]
"""
import glob, os, sys
import numpy as np
import pandas as pd

DIR = sys.argv[1]
WIN = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0
TRAIN_FRAC = float(sys.argv[3]) if len(sys.argv) > 3 else 0.75

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import HINTS, USECOLS, load, windows
from detector import FLOOD_FLOOR, Detector


files = sorted(glob.glob(os.path.join(DIR, "*.csv")) + glob.glob(os.path.join(DIR, "*.csv.gz")))
n_train = max(1, int(round(len(files) * TRAIN_FRAC)))
if n_train >= len(files) and len(files) > 1:
    n_train = len(files) - 1
train_files, test_files = files[:n_train], files[n_train:]
print(f"[1] {len(files)} files: {len(train_files)} train / {len(test_files)} held-out test")

# One file at a time: a week of baseline is ~100M frames, far more than RAM,
# but its per-second feature table is small. (10 s / 60 s rolling features
# restart at each file boundary — negligible with 5-min files.)
_parts, known_pairs, _ssid_files, _arp_last = [], set(), {}, {}
for _p in train_files:
    _d = load(_p)
    _f, _pairs = windows(_d, WIN)
    _parts.append(_f)
    known_pairs |= _pairs
    _bcn = _d[(_d["wlan.fc.type"] == 0) & (_d["wlan.fc.subtype"] == 8)]
    for _ssid in _bcn["wlan.ssid"].dropna().unique():
        _ssid_files[_ssid] = _ssid_files.get(_ssid, 0) + 1
    _a = _d[_d["arp.src.proto_ipv4"].notna() & _d["arp.src.hw_mac"].notna()]
    _arp_last.update(_a.groupby("arp.src.proto_ipv4")["arp.src.hw_mac"].last().to_dict())
    del _d
ftr = pd.concat(_parts)
arp_seed = pd.DataFrame(list(_arp_last.items()), columns=["arp.src.proto_ipv4", "arp.src.hw_mac"])
# Only guard SSIDs that are infrastructure: seen in (nearly) every training
# file. A transient hotspot (e.g. a phone that appears for 15 min) isn't
# protected, so it re-appearing with a fresh random MAC isn't "evil twin".
protected_ssids = {k for k, v in _ssid_files.items() if v >= 0.9 * len(train_files)}
transient_ssids = set(_ssid_files) - protected_ssids
known_pairs = {(s_, b_) for s_, b_ in known_pairs if s_ in protected_ssids}
# drop each file's partial first/last window
ftr = ftr.groupby("file", group_keys=False).apply(lambda x: x.iloc[1:-1])
FEATS = [c for c in ftr.columns if c != "file"]
Xtr = ftr[FEATS]
print(f"[2] train: {len(Xtr):,} windows × {len(FEATS)} features ({WIN:g}s each); "
      f"{len(known_pairs)} known (SSID, BSSID) pairs")

det = Detector(Xtr)
model, thr, med, iqr, z_limit, never_seen = det.model, det.thr, det.med, det.iqr, det.z_limit, det.never_seen
b_hits, explain = det.b_hits, det.explain


print(f"[3] A) IsolationForest threshold = {thr:.3f} (99.5th pct of train)")
print(f"    B) single-occurrence rules: {never_seen}; ARP bindings learned: {len(arp_seed)}")
print(f"    B) protected SSIDs (evil-twin guarded): {sorted(protected_ssids)}")
print(f"       transient SSIDs (not guarded): {sorted(transient_ssids)}")
print("       flood limits/s: " + ", ".join(f"{f}>{max(Xtr[f].max()*1.2, v):g}" for f, v in FLOOD_FLOOR.items()))

if test_files:
    fte = pd.concat([windows(load(p), WIN, known_pairs, arp_seed)[0] for p in test_files])
    fte = fte.groupby("file", group_keys=False).apply(lambda x: x.iloc[1:-1])
    Xte = fte[FEATS]
    te_scores = -model.score_samples(Xte)
    a_alert = te_scores > thr
    b_alert = np.array([bool(b_hits(Xte.loc[w])) for w in Xte.index])
    n = len(Xte)
    print(f"\n[4] False alarms on HELD-OUT normal data ({n:,} windows ≈ {n*WIN/60:.0f} min):")
    print(f"    A) IsolationForest: {a_alert.sum()} ({100*a_alert.mean():.2f}%)  "
          f"≈ {a_alert.sum()/(n*WIN/3600):.1f} alerts/hour")
    print(f"    B) per-feature:     {b_alert.sum()} ({100*b_alert.mean():.2f}%)  "
          f"≈ {b_alert.sum()/(n*WIN/3600):.1f} alerts/hour")
    print(f"    A or B:             {(a_alert | b_alert).sum()}")

    def events(mask, gap=2):
        # consecutive alert windows (≤gap apart) = one event
        idx = Xte.index[mask]
        return 0 if len(idx) == 0 else 1 + int((np.diff(idx) > gap).sum())
    hours = n * WIN / 3600
    for name, m in [("A", a_alert), ("B", b_alert), ("A or B", a_alert | b_alert)]:
        e = events(m)
        print(f"    as EVENTS (merging back-to-back seconds) {name:<6}: {e} ≈ {e/hours:.1f} events/hour")
    print("    B alerts on held-out (what triggered them):")
    for w in Xte.index[b_alert]:
        row = Xte.loc[w]
        print(f"     {pd.to_datetime(w*WIN, unit='s', utc=True).tz_convert('Asia/Bangkok'):%H:%M:%S} "
              + ", ".join(f"{h}={row[h]:.2f} (train max {Xtr[h].max():.2f})" for h in b_hits(row)))
    top = pd.Series(te_scores, index=Xte.index).nlargest(5).index
    print("    most unusual held-out windows:")
    for w in top:
        row = Xte.loc[w]
        hits = b_hits(row)
        why = explain(row) or ["(combined mild deviation)"]
        print(f"     {pd.to_datetime(w*WIN, unit='s', utc=True).tz_convert('Asia/Bangkok'):%H:%M:%S} "
              f"A={'ALERT' if te_scores[Xte.index.get_loc(w)] > thr else 'ok'} "
              f"B={'ALERT' if hits else 'ok'} | " + " | ".join(why))

print("\n[5] Synthetic attack injection (edits a median window — not real attack traffic):")
base = Xtr.median()
tests = {
    "Deauth flood 200/s": {"deauth": 200, "mgmt": "+200", "frames": "+200"},
    "Targeted deauth 5/s (stealthy)": {"deauth": 5, "mgmt": "+5", "frames": "+5"},
    "Disassoc flood 50/s": {"disassoc": 50, "mgmt": "+50", "frames": "+50"},
    "Beacon flood 300 fake APs": {"beacon": "+300", "n_ssid": "+300", "n_bssid": "+300", "mgmt": "+300", "frames": "+300"},
    "Evil twin (1 extra KUWIN AP)": {"max_bssid_per_ssid": "+1", "new_bssid_known_ssid": 1, "n_bssid": "+1", "beacon": "+10"},
    "ARP spoofing": {"arp": "+40", "arp_reply_ratio": 1.0, "data": "+40", "frames": "+40"},
    "Rogue DHCP flood": {"dhcp": "+60", "data": "+60", "frames": "+60"},
    "RTS flood 500/s": {"rts": "+500", "ctrl": "+500", "frames": "+500"},
}
for name, ch in tests.items():
    row = base.copy()
    for k, v in ch.items():
        row[k] = base[k] + float(v[1:]) if isinstance(v, str) else v
    a = -model.score_samples(row[FEATS].to_frame().T)[0] > thr
    hits = b_hits(row)
    types = sorted({HINTS[h] for h in hits if h in HINTS})
    print(f"  {name:<30} A={'✓' if a else '✗'}  B={'✓' if hits else '✗'}  → {', '.join(types) or '-'}")


# ---------------------------------------------------------------------------
# [6] Frame-level injection: append synthetic attack FRAMES (CSV rows, same
# columns the app writes) into the real held-out capture, then run the whole
# pipeline (windowing -> features -> detectors) on it. More realistic than
# editing feature values, but the radio properties are still chosen by us.
# ---------------------------------------------------------------------------
if test_files:
    # inject into the last 2 held-out files only (bounded RAM on long baselines)
    base_df = pd.concat([load(p) for p in test_files[-2:]], ignore_index=True)
    AP, SSID, CLIENT = "00:df:1d:d7:12:af", "KUWIN", "d4:d8:53:24:f9:eb"
    t_start = base_df["frame.time_epoch"].min()
    ref = base_df.dropna(subset=["radiotap.mactime"]).iloc[0]
    mac_at = lambda t: ref["radiotap.mactime"] + (t - ref["frame.time_epoch"]) * 1e6
    real_bcn = base_df[(base_df["wlan.bssid"] == AP) & (base_df["wlan.fc.subtype"] == 8)
                       & (base_df["wlan.fc.type"] == 0)]
    # Pick a quiet stretch: no A or B alert in the 15 s before through 75 s
    # after, so whatever fires during the test is caused by the injected frames.
    X0, _ = windows(base_df, WIN, known_pairs, arp_seed)
    X0 = X0[FEATS]
    a0 = pd.Series(-model.score_samples(X0) > thr, index=X0.index)
    b0 = {w: set(b_hits(X0.loc[w])) for w in X0.index}
    busy = {w for w in X0.index if a0[w] or b0[w]}
    T0 = None
    for w in X0.index[60:]:
        if not any(x in busy for x in range(w - 15, w + 76)):
            T0 = float(w * WIN)
            break
    if T0 is None:
        sys.exit("no quiet 90 s stretch in held-out data to inject into")
    # The AP's clock drifts vs. our adapter's (ppm-level -> ms over minutes),
    # so take the real offset right at the injection time, not a 15-min median.
    near = real_bcn[(real_bcn["frame.time_epoch"] - T0).abs() < 5]
    real_off = (near["wlan.fixed.timestamp"] - near["radiotap.mactime"]).median()
    drift = (real_bcn["wlan.fixed.timestamp"] - real_bcn["radiotap.mactime"])
    print(f"\n    (AP clock offset drift over the held-out 15 min: {drift.max() - drift.min():,.0f} µs)")

    def frame(t, **kw):
        r = {c: np.nan for c in USECOLS}
        r.update({"frame.time_epoch": t, "frame.len": 60, "wlan.fc.retry": 0, "wlan.fc.protected": 0,
                  "radiotap.mactime": mac_at(t), "file": "INJECTED"})
        r.update(kw)
        return r

    def deauth(t, seq):
        return frame(t, **{"wlan.fc.type": 0, "wlan.fc.subtype": 12, "wlan.ra": CLIENT, "wlan.da": CLIENT,
                           "wlan.ta": AP, "wlan.sa": AP, "wlan.bssid": AP, "wlan_radio.signal_dbm": -46,
                           "wlan.seq": seq % 4096})

    rb = real_bcn[["frame.time_epoch", "wlan.seq"]].dropna().sort_values("frame.time_epoch")
    def ap_seq_now(t):  # an advanced attacker sniffing the AP's current counter
        return int(rb[rb["frame.time_epoch"] <= t]["wlan.seq"].iloc[-1]) + 1

    def clone_beacon(t, signal, tsf_off):
        return frame(t, **{"frame.len": 300, "wlan.fc.type": 0, "wlan.fc.subtype": 8, "wlan.ssid": SSID,
                           "wlan.ra": "ff:ff:ff:ff:ff:ff", "wlan.da": "ff:ff:ff:ff:ff:ff", "wlan.ta": AP,
                           "wlan.sa": AP, "wlan.bssid": AP, "wlan_radio.signal_dbm": signal,
                           "wlan.fixed.timestamp": mac_at(t) + tsf_off})

    def every(start, dur, per_s):
        return [start + i / per_s for i in range(int(dur * per_s))]

    scenarios = {
        "Spoofed targeted deauth 1/s × 20s, attacker's own seq":
            [deauth(t, 100 + i) for i, t in enumerate(every(T0, 20, 1))],
        "Spoofed targeted deauth 5/s × 10s, attacker's own seq":
            [deauth(t, 100 + i) for i, t in enumerate(every(T0, 10, 5))],
        "Spoofed targeted deauth 1/s × 20s, copies AP's seq (advanced)":
            [deauth(t, ap_seq_now(t)) for t in every(T0, 20, 1)],
        "Cloned-BSSID twin, other location (-30 dBm), own clock":
            [clone_beacon(t, -30, real_off + 7.3e9) for t in every(T0, 30, 4)],
        "Cloned-BSSID twin, SAME signal (-46 dBm), own clock":
            [clone_beacon(t, -46, real_off + 7.3e9) for t in every(T0, 30, 4)],
        "Cloned-BSSID twin, same signal, clock copied to 0.2 ms":
            [clone_beacon(t, -46, real_off + 200) for t in every(T0, 30, 4)],
    }

    # ARP spoofing scenarios need the ARP address columns (captures from
    # 2026-10-08 ~14:30 onward); skipped on older baselines.
    replies = base_df[(base_df["arp.opcode"] == 2) & base_df["arp.src.proto_ipv4"].notna()]
    if len(replies):
        GW_IP, GW_MAC = replies.groupby(["arp.src.proto_ipv4", "arp.src.hw_mac"]).size().idxmax()
        ATTACKER, ATTACKER_IP = "02:de:ad:be:ef:01", "10.255.255.77"

        def arp_reply(t, mac, ip):
            return frame(t, **{"wlan.fc.type": 2, "wlan.fc.subtype": 0, "arp.opcode": 2,
                               "arp.src.hw_mac": mac, "arp.src.proto_ipv4": ip,
                               "wlan.sa": mac, "wlan.ta": AP, "wlan.bssid": AP,
                               "wlan_radio.signal_dbm": -60})
        print(f"\n    (ARP scenarios impersonate the most-answered IP in the data: {GW_IP} @ {GW_MAC})")
        scenarios.update({
            "ARP spoof: attacker says 'GW is me' every 2s, real GW also answers":
                [arp_reply(t, ATTACKER, GW_IP) for t in every(T0, 30, 0.5)]
                + [arp_reply(t + 1, GW_MAC, GW_IP) for t in every(T0, 30, 0.5)],
            "ARP spoof: attacker claims GW + own IP every 2s (real GW silent)":
                [arp_reply(t, ATTACKER, GW_IP) for t in every(T0, 30, 0.5)]
                + [arp_reply(t + 0.5, ATTACKER, ATTACKER_IP) for t in every(T0, 30, 0.5)],
            "ARP spoof, stealthy: 1 poisoning reply per 10s, nothing else":
                [arp_reply(t, ATTACKER, GW_IP) for t in every(T0, 60, 0.1)],
        })

    print("\n[6] Frame-level injection into real held-out traffic (whole pipeline):")
    print(f"    injected at a quiet stretch starting "
          f"{pd.to_datetime(T0, unit='s', utc=True).tz_convert('Asia/Bangkok'):%H:%M:%S}; "
          f"only alerts ADDED by the injected frames are counted")
    for name, rows in scenarios.items():
        inj = pd.concat([base_df, pd.DataFrame(rows)], ignore_index=True)
        inj["file"] = inj["file"].where(inj["file"] != "INJECTED", np.nan)
        inj = inj.sort_values("frame.time_epoch", kind="stable")
        inj["file"] = inj["file"].ffill()
        X, _ = windows(inj, WIN, known_pairs, arp_seed)
        t_end = max(r["frame.time_epoch"] for r in rows)
        span = X.loc[int(T0 // WIN): int(t_end // WIN) + 10, FEATS]
        # only count what the injected frames ADDED vs. the same windows without them
        a = (-model.score_samples(span) > thr) & ~a0.reindex(span.index, fill_value=False).to_numpy()
        hits = {w: [h for h in b_hits(span.loc[w]) if h not in b0.get(w, set())] for w in span.index}
        b_win = [w for w, h in hits.items() if h]
        feats_hit = sorted({h for w in b_win for h in hits[w]})
        types = sorted({HINTS[h] for h in feats_hit if h in HINTS})
        delay = f"{(b_win[0] * WIN - T0):.0f}s after start" if b_win else "-"
        print(f"  {name:<56} A={'✓' if a.any() else '✗'}  B={'✓' if b_win else '✗'}  first B alert: {delay}")
        if feats_hit:
            print(f"     triggered: {', '.join(feats_hit)}")
            print(f"     → {', '.join(types)}")
