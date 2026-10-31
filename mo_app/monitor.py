"""
Live monitor (POC): continuous capture -> per-second features -> detectors
A/B -> alerts, while the baseline keeps growing and the detectors are refitted
periodically. "Brain Power" says how much to trust them yet.

Everything persists under captures/monitor/:
    raw/capture_*.csv.gz   every frame, 5-minute gzip chunks (same columns as the app's CSVs)
    raw/capture_*.json     sidecar per chunk: iface/channel, versions, git revision, start/end, frames
    features.csv           one row per second: the 36 features + what was flagged
    alerts.jsonl           one line per alert event
    context.json           learned infrastructure: SSID/BSSID pairs, ARP bindings, retrain history

See anomaly_detection_notes.md for the reasoning behind features/rules/Brain Power.
"""
import csv
import gzip
import io
import json
import math
import os
import shutil
import subprocess
import threading
import time
from collections import deque

import numpy as np
import pandas as pd

from capture import (FIELD_ORDER, GIT_REVISION, MISSING, RAW_SCHEMA_VERSION, check_monitor_mode, csv_row,
                     extract_fields, iface_channel_info, set_monitor_mode, write_sidecar)
from analysis.detector import Detector
from analysis.features import FEATURE_VERSION, GENERIC, HINTS, clean, load, windows
from model_c_client import ModelCClient

CHUNK_SECONDS = 300          # raw file rotation
ANALYSIS_EVERY = 5           # seconds between detection passes
LOOKBACK = 90                # seconds of frames kept for rolling (10 s / 60 s) features
SETTLE = 3                   # don't judge a second until this many have passed (next-beacon lookahead)
RETRAIN_EVERY = 600          # seconds
MIN_TRAIN_WINDOWS = 300
SLOT_TARGET = 1800           # windows (= 30 min) per hour-of-week slot to call it "covered"
FA_TARGET, FA_WORST = 1.0, 30.0   # alert events/hour mapped to Brain Power FA score 1 .. 0
# Brain Power's FA rate = median hourly alarm rate on unseen data over 24 h.
# Was 6 h: on 2026-10-13 model A got trusted at 04:08 on a quiet night alone,
# then failed as soon as Monday-morning traffic arrived.
FA_HORIZON = 24 * 3600
MIN_FA_HOURS = 20               # trust model A only if ≥ 20 of those 24 h were measured
# Model A becomes "trusted" (its alerts are then kept out of training) only
# when Brain Power >= 50 AND it is actually quiet on unseen data; it loses
# that only after 24 h of continuously failing, so a burst of alerts — e.g. a
# real attack — can't knock it back into learning mode and get learned.
TRUST_BP, TRUST_FA, DISTRUST_AFTER = 50.0, 5.0, 24 * 3600

# Which stored seconds detectors A/B are trained on, and how long data is
# kept (set from the dashboard's Training data card, saved in context.json).
#   mode "roll": the last `days` days; "pick": the local dates in `chosen`;
#   "all": everything. `excludes` periods are never trained on, whatever the
#   mode (attack tests; a pause adds one automatically).
DEFAULT_POLICY = {
    "mode": "roll", "days": 28, "chosen": [], "excludes": [], "pause_until": None,
    "raw_retention": {"enabled": True, "days": 30},
    "feat_retention": {"enabled": False, "days": 180},
}
MIN_TRAIN_DAYS = 7           # a shorter window can't cover every hour of the week
CLEANUP_HOUR = 3             # local hour of the daily retention run


def _intervals(pairs):
    """[(start, end), ...] inclusive -> merged, sorted (starts, ends) arrays."""
    pairs = sorted((int(a), int(b)) for a, b in pairs if b >= a)
    merged = []
    for a, b in pairs:
        if merged and a <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    arr = np.array(merged, dtype="int64").reshape(-1, 2)
    return arr[:, 0], arr[:, 1]


def _in_intervals(wins, iv):
    """Boolean mask: which of `wins` fall inside any of the intervals `iv`."""
    starts, ends = iv
    if not len(starts):
        return np.zeros(len(wins), dtype=bool)
    i = np.searchsorted(starts, wins, side="right") - 1
    return (i >= 0) & (wins <= ends[np.clip(i, 0, None)])


def _local_day(ts):
    """Local date "YYYY-MM-DD" of a unix time (Thailand: no DST)."""
    return time.strftime("%Y-%m-%d", time.localtime(ts))


class _ChunkWriter:
    """Writes frames to gzip CSV chunks as each second completes, so memory
    stays flat over days (CaptureSession buffers the whole capture instead).
    n_unique_dest_mac_per_sec is per-second, so it can be filled per second.

    meta() returns the capture settings for each chunk's .json sidecar."""

    def __init__(self, out_dir, meta=dict):
        self.out_dir = out_dir
        self.meta = meta
        self.pending = {}
        self.f = self.w = self.path = None
        self.opened_at = 0
        self.side = None

    def add(self, row):
        t = row.get("frame.time_epoch", MISSING)
        if t != MISSING:
            self.pending.setdefault(int(t), []).append(row)

    def flush(self, now, force=False):
        if self.f is None:
            self._rotate(now)
        # write the finished seconds before rotating, so they land in the
        # chunk they belong to rather than at the start of the next one
        for sec in sorted(s for s in self.pending if force or s < int(now) - 1):
            rows = self.pending.pop(sec)
            n_da = len({r["wlan.da"] for r in rows if r.get("wlan.da", MISSING) != MISSING})
            for r in rows:
                if n_da:
                    r["n_unique_dest_mac_per_sec"] = n_da
                self.w.writerow(csv_row(r))
            self.side["frames"] += len(rows)
            self.side["first_second"] = self.side["first_second"] or sec
            self.side["last_second"] = sec
        if now - self.opened_at >= CHUNK_SECONDS:
            self._rotate(now)

    def _rotate(self, now):
        self.close()
        os.makedirs(self.out_dir, exist_ok=True)
        self.path = os.path.join(self.out_dir, time.strftime("capture_%Y%m%d_%H%M%S.csv.gz", time.localtime(now)))
        self.f = gzip.open(self.path, "wt", newline="")
        self.w = csv.DictWriter(self.f, fieldnames=FIELD_ORDER, extrasaction="ignore")
        self.w.writeheader()
        self.opened_at = now
        self.side = {"source": "monitor", **self.meta(),
                     "raw_schema_version": RAW_SCHEMA_VERSION, "feature_version": FEATURE_VERSION,
                     "git_revision": GIT_REVISION, "started_at": now, "ended_at": None,
                     "first_second": None, "last_second": None, "frames": 0}
        self._write_side()

    def _write_side(self):
        try:
            write_sidecar(self.path, self.side)
        except OSError:
            pass                    # metadata only: never stop the capture over it

    def close(self):
        if self.f is not None:
            self.f.close()
            self.f = self.w = None
            self.side["ended_at"] = time.time()
            self._write_side()


def _jsonable(o):
    """NaN/inf -> None (Python's json writes them as bare NaN, which browsers reject)."""
    if isinstance(o, dict):
        return {k: _jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_jsonable(v) for v in o]
    if isinstance(o, (float, np.floating)):
        return float(o) if math.isfinite(o) else None
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.bool_):
        return bool(o)
    return o


class _Replayer(threading.Thread):
    """Plays a recorded capture back at real speed, re-timed to start now."""

    def __init__(self, path, on_row):
        super().__init__(daemon=True)
        self.path, self.on_row, self._stop = path, on_row, threading.Event()

    def run(self):
        opener = gzip.open if self.path.endswith(".gz") else open
        with opener(self.path, "rt", newline="") as f:
            t_first, start = None, time.time()
            for raw in csv.DictReader(f):
                if self._stop.is_set():
                    return
                row = {k: (MISSING if v in ("-1", "") else v) for k, v in raw.items()}
                t = float(row["frame.time_epoch"])
                t_first = t if t_first is None else t_first
                due = start + (t - t_first)
                if due > time.time():
                    if self._stop.wait(due - time.time()):
                        return
                row["frame.time_epoch"] = due
                if row.get("radiotap.mactime", MISSING) != MISSING:
                    row["radiotap.mactime"] = float(row["radiotap.mactime"])
                self.on_row(row)

    def stop(self):
        self._stop.set()


class LiveMonitor:
    def __init__(self, base_dir):
        self.dir = base_dir
        self.raw_dir = os.path.join(base_dir, "raw")
        self.feat_path = os.path.join(base_dir, "features.csv")
        self.alert_path = os.path.join(base_dir, "alerts.jsonl")
        self.ctx_path = os.path.join(base_dir, "context.json")
        os.makedirs(self.raw_dir, exist_ok=True)

        self.lock = threading.Lock()
        self.running = False
        self.iface = self.channel = self.width = self.replay = None
        self.error = None
        self.log = deque(maxlen=50)

        # learned context (persisted)
        self.ctx = {"ssid_chunks": {}, "n_chunks": 0, "pairs": [], "arp": {},
                    "imported": [], "retrains": []}
        if os.path.exists(self.ctx_path):
            with open(self.ctx_path) as f:
                self.ctx.update(json.load(f))
        self._feat_parts, self._feat_cache = [], None
        self.slot_counts, self.n_feat_rows = np.zeros((7, 24)), 0
        if os.path.exists(self.feat_path) and self.ctx.get("feature_version") != FEATURE_VERSION:
            self._rebuild_features()
        elif os.path.exists(self.feat_path):
            # NUL padding = file cut off by a power loss/reboot (seen 2026-10-08)
            raw = open(self.feat_path, "rb").read().replace(b"\x00", b"")
            text = raw.decode("utf-8", "ignore")
            self._remember(pd.read_csv(io.StringIO(text[:text.rfind("\n") + 1])).dropna(subset=["win"]))
        self.alerts = self._read_alerts()[-500:]
        if self.ctx.get("trust_rule") != 2:
            # trust granted under the old 6-hour rule doesn't count
            self.ctx.update(a_trusted=False, trust_rule=2)
            self.ctx.pop("distrust_since", None)
        self.ctx.setdefault("pending_aps", {})
        pol = {**DEFAULT_POLICY, **self.ctx.get("train_policy", {})}
        self.ctx["train_policy"] = pol
        self._retrain_requested = False
        self._sel_cache = (None, None)

        self.detector = None
        self.feats = None
        self.last_retrain = 0
        self.last_eval = None
        self.snapshot = {}
        # Model C runs on the training machine; shadow mode until validated
        self.model_c = ModelCClient(os.path.join(base_dir, "model_c_shadow.jsonl"), log=self._log)
        self._retrain()

    # ------------------------------------------------------------------ control
    def start(self, iface, channel="100", width="HT40+", replay=None):
        """replay: path of a recorded capture CSV(.gz) to play back in real time
        instead of sniffing — for trying the dashboard without the adapter/root."""
        with self.lock:
            if self.running:
                return False, "already running"
        if replay is None:
            ok, msg = self._prepare(iface, channel, width)
            if not ok:
                return False, msg
        elif not os.path.exists(replay):
            return False, f"replay file not found: {replay}"
        with self.lock:
            self.replay = replay
            self.iface, self.channel, self.width = (iface, channel, width) if replay is None else \
                (f"replay:{os.path.basename(replay)}", "-", "-")
            self.running, self.error = True, None
            self.started_at = time.time()
            self.frames_total, self.restarts = 0, 0
            self.recent = deque()
            self.writer = _ChunkWriter(self.raw_dir, self._chunk_meta)
            self.chunk_pairs, self.chunk_ssids = set(), set()
            self.last_win = int(time.time()) - SETTLE
            self.last_frame_at = time.time()
            self._xstate = {"prev_time": None, "count": 0, "seen_tcp_seqs": set()}
        if replay is None:
            from scapy.all import AsyncSniffer
            self._sniffer_cls = AsyncSniffer
            self._start_sniffer()
        else:
            self.sniffer = _Replayer(replay, self._on_row)
            self.sniffer.start()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        self._log(f"started on {self.iface} ch{self.channel} {self.width}")
        if replay is None:
            # resume after an app/service restart or reboot (see resume())
            self.ctx["autostart"] = {"iface": iface, "channel": channel, "width": width}
            self._save_ctx()
        return True, "ok"

    def resume(self):
        """Restart monitoring if it was running when the app last went down.
        At boot the USB adapter may not exist yet, so keep trying for ~5 min."""
        cfg = self.ctx.get("autostart")
        if not cfg:
            return

        def attempt():
            for _ in range(30):
                ok, msg = self.start(cfg["iface"], cfg["channel"], cfg["width"])
                if ok or msg == "already running":
                    self._log("resumed monitoring after restart")
                    return
                self._log(f"resume failed ({msg}); retrying in 10 s")
                time.sleep(10)
        threading.Thread(target=attempt, daemon=True).start()

    def stop(self, remember=True):
        """remember=False: the user asked to stop, so don't resume on restart."""
        if not remember:
            self.ctx.pop("autostart", None)
            self._save_ctx()
        with self.lock:
            if not self.running:
                return
            self.running = False
        try:
            self.sniffer.stop()
        except Exception:
            pass
        self.thread.join(timeout=15)
        with self.lock:
            self.writer.flush(time.time(), force=True)
            self.writer.close()
            self._close_chunk()
        self._save_ctx()
        self._log("stopped")

    def _chunk_meta(self):
        info = iface_channel_info(self.iface) if self.replay is None else None
        return {"iface": self.iface, "channel": self.channel, "width": self.width, "channel_info": info}

    def _prepare(self, iface, channel, width):
        ok, msg = check_monitor_mode(iface)
        if not ok:
            ok, msg = set_monitor_mode(iface)
            if not ok:
                return False, msg
        r = subprocess.run(["iw", "dev", iface, "set", "channel", str(channel)] + ([width] if width else []),
                           capture_output=True, text=True)
        if r.returncode != 0:
            return False, f"could not set channel: {r.stderr.strip()}"
        return True, "ok"

    def _start_sniffer(self):
        self.sniffer = self._sniffer_cls(iface=self.iface, prn=self._on_packet, store=False)
        self.sniffer.start()

    def _on_packet(self, pkt):
        st = self._xstate
        st["count"] += 1
        try:
            row = extract_fields(pkt, st["count"], self.started_at, st["prev_time"], st, llc_snap_dispatch=True)
        except Exception:
            return
        st["prev_time"] = row["frame.time_epoch"]
        self._on_row(row)

    def _on_row(self, row):
        with self.lock:
            self.recent.append(row)
            self.writer.add(row)
            self.frames_total += 1
            self.last_frame_at = time.time()

    # --------------------------------------------------------------- main loop
    def _loop(self):
        while True:
            time.sleep(ANALYSIS_EVERY)
            with self.lock:
                if not self.running:
                    return
            try:
                self._tick()
            except Exception as e:  # keep the sensor alive; surface the error
                self.error = f"{type(e).__name__}: {e}"
                self._log(f"analysis error: {self.error}")

    def _tick(self):
        now = time.time()
        with self.lock:
            rotated_from = self.writer.path
            self.writer.flush(now)
            if self.writer.path != rotated_from and rotated_from is not None:
                self._close_chunk()
            while self.recent and self.recent[0]["frame.time_epoch"] < now - LOOKBACK:
                self.recent.popleft()
            rows = list(self.recent)
            silent_for = now - self.last_frame_at

        self._watchdog(silent_for)
        if not rows:
            self._build_snapshot(pd.DataFrame(), now)
            return

        df = clean(pd.DataFrame(rows), "live")
        known_pairs, arp_seed = self._known_pairs(), self._arp_seed()
        self._pass_known = known_pairs
        f, _ = windows(df, 1, known_pairs, arp_seed)
        new = f[(f.index > self.last_win) & (f.index <= int(now) - SETTLE)]
        if len(new):
            self.last_win = int(new.index.max())
            self._judge(new, df)
            self.model_c.submit(f, new.index)
        self._build_snapshot(df, now)
        if self._retrain_requested or now - self.last_retrain >= RETRAIN_EVERY:
            self._retrain_requested = False
            self._retrain()
        self._daily_cleanup(now)

    def _judge(self, new, df):
        feats = self.feats or [c for c in new.columns if c != "file"]
        X = new.reindex(columns=feats).fillna(0)
        out = X.copy()
        out["a_score"], out["a_alert"], out["b_alert"] = np.nan, False, False
        if self.detector is not None:
            out["a_score"] = self.detector.scores(X)
            out["a_alert"] = out["a_score"] > self.detector.thr
            unknown = self._unknown_aps(df, X.index)
            for w in X.index:
                hits = self.detector.b_hits(X.loc[w])
                details = None
                if "new_bssid_known_ssid" in hits:
                    first_time = self._track_pending(unknown.get(w, {}))
                    if first_time:
                        details = {"new_bssids": first_time}
                    else:
                        # already reported and waiting for approval: one alert per
                        # BSSID, not one per second it's heard (11,541 of them over
                        # 2026-10-09..13 for new campus APs a4:6c:2a / cc:16:7e)
                        hits = [h for h in hits if h != "new_bssid_known_ssid"]
                out.loc[w, "b_alert"] = bool(hits)
                if hits or out.loc[w, "a_alert"]:
                    self._raise(w, X.loc[w], hits, float(out.loc[w, "a_score"]), details)
        out.insert(0, "win", out.index)
        self._append_features(out)

        # learn infrastructure only from seconds nobody flagged (anti-poisoning)
        clean_wins = set(out.index[~(out["a_alert"] | out["b_alert"])])
        ok = df[(df["frame.time_epoch"] // 1).isin(clean_wins)]
        bcn = ok[(ok["wlan.fc.type"] == 0) & (ok["wlan.fc.subtype"] == 8)].dropna(subset=["wlan.ssid", "wlan.bssid"])
        # an AP waiting for approval is never learned as known just by being heard
        bcn = bcn[~bcn["wlan.bssid"].isin(self.ctx["pending_aps"].keys())]
        a = ok.dropna(subset=["arp.src.proto_ipv4", "arp.src.hw_mac"])
        a = a[(a["arp.src.proto_ipv4"] != "0.0.0.0") & (a["arp.src.hw_mac"] != "00:00:00:00:00:00")]
        if self.paused():
            return                  # learning paused (attack test): learn nothing
        with self.lock:
            self.chunk_pairs |= set(zip(bcn["wlan.ssid"], bcn["wlan.bssid"]))
            self.chunk_ssids |= set(bcn["wlan.ssid"])
            self.ctx["arp"].update(dict(zip(a["arp.src.proto_ipv4"], a["arp.src.hw_mac"])))

    def _unknown_aps(self, df, wins):
        """{window: {bssid: {"ssids": set, "signal": dBm}}} for beacons of a
        protected SSID from a BSSID not known for it."""
        prot, known = self._protected(), getattr(self, "_pass_known", set())
        b = df[(df["wlan.fc.type"] == 0) & (df["wlan.fc.subtype"] == 8)].dropna(subset=["wlan.ssid", "wlan.bssid"])
        b = b[b["wlan.ssid"].isin(prot) & (b["frame.time_epoch"] // 1).isin(set(wins))]
        out = {}
        for (w, bssid), g in b.groupby([b["frame.time_epoch"] // 1, "wlan.bssid"]):
            ssids = {s for s in g["wlan.ssid"] if (s, bssid) not in known}
            if ssids:
                out.setdefault(int(w), {})[bssid] = {"ssids": ssids, "signal": float(g["wlan_radio.signal_dbm"].median())}
        return out

    def _track_pending(self, seen):
        """Update the pending-approval list; return the BSSIDs seen for the
        first time (only those raise an alert)."""
        now, first = time.time(), []
        pend = self.ctx["pending_aps"]
        for bssid, info in seen.items():
            p = pend.get(bssid)
            if p is None:
                first.append(bssid)
                p = pend[bssid] = {"ssids": [], "first_seen": now, "seconds": 0,
                                   "local_admin": bool(int(bssid[:2], 16) & 2)}
            p["ssids"] = sorted(set(p["ssids"]) | info["ssids"])
            p["last_seen"], p["signal"] = now, round(info["signal"], 1) if info["signal"] == info["signal"] else None
            p["seconds"] += 1
        return first

    def approve_aps(self, bssids):
        """Accept pending APs as legitimate infrastructure (one decision per AP)."""
        done = []
        for b in bssids:
            p = self.ctx["pending_aps"].pop(b, None)
            if p:
                self.ctx["pairs"] = sorted(set(map(tuple, self.ctx["pairs"])) | {(s, b) for s in p["ssids"]})
                self.ctx.setdefault("approved_aps", {})[b] = {"ssids": p["ssids"], "approved_at": time.time()}
                done.append(b)
        self._save_ctx()
        if done:
            self._log(f"approved {len(done)} AP(s): {', '.join(done)}")
        return done

    def _raise(self, w, row, hits, a_score, details=None):
        attack = [h for h in hits if h in HINTS]
        detector = "A+B" if hits and a_score > self.detector.thr else ("B" if hits else "A")
        # Levels: "rule" = an attack-specific rule fired (trusted from day 1);
        # "info" = only general traffic features exceeded the baseline;
        # "low (still learning)" / "normal" = model A alone, before / after
        # Brain Power reaches 50.
        if attack:
            confidence, types = "rule", sorted({HINTS[h] for h in attack})
        elif hits:
            confidence, types = "info", sorted({GENERIC.get(h, f"Unusual {h}") for h in hits})
        else:
            confidence = "normal" if self.ctx.get("a_trusted") else "low (still learning)"
            types = ["Unusual combination of traffic features (model A — type unknown)"]
        last = self.alerts[-1] if self.alerts else None
        # a newly seen BSSID is always its own event so it is written to alerts.jsonl
        if (not details and last and 0 <= w - last["end"] <= 3
                and last["detector"] == detector and last["confidence"] == confidence):
            last["end"], last["seconds"] = int(w), last["seconds"] + 1
            last["types"] = sorted(set(last["types"]) | set(types))
            last["peak_score"] = max(last["peak_score"], a_score)
            return
        ev = {
            "start": int(w), "end": int(w), "seconds": 1, "detector": detector,
            "types": types,
            "features": {h: round(float(row[h]), 3) for h in hits},
            **({"details": details} if details else {}),
            "explain": self.detector.explain(row),
            "peak_score": a_score,
            "confidence": confidence,
        }
        self.alerts.append(ev)
        self.alerts = self.alerts[-500:]
        with open(self.alert_path, "a") as f:
            f.write(json.dumps(ev) + "\n")
            f.flush()
            os.fsync(f.fileno())

    @property
    def features(self):
        if self._feat_cache is None:
            self._feat_cache = pd.concat(self._feat_parts, ignore_index=True) if self._feat_parts else pd.DataFrame()
            self._feat_parts = [self._feat_cache] if self._feat_parts else []
        return self._feat_cache

    def _remember(self, out):
        self._feat_parts.append(out)
        self._feat_cache = None
        self.n_feat_rows += len(out)
        # hour-of-week slot counts, local time (no DST in Thailand)
        local = out["win"].astype("int64").to_numpy() - time.timezone
        np.add.at(self.slot_counts, (((local // 86400) + 3) % 7, (local % 86400) // 3600), 1)

    def _append_features(self, out):
        if os.path.exists(self.feat_path):
            cols = pd.read_csv(self.feat_path, nrows=0).columns
            with open(self.feat_path, "a") as fh:
                out.reindex(columns=cols).to_csv(fh, header=False, index=False)
                fh.flush()
                os.fsync(fh.fileno())
        else:
            out.to_csv(self.feat_path, index=False)
            self.ctx["feature_version"] = FEATURE_VERSION
        self._remember(out)

    def _close_chunk(self):
        """A finished 5-min chunk counts toward 'which SSIDs are infrastructure'."""
        for s in self.chunk_ssids:
            self.ctx["ssid_chunks"][s] = self.ctx["ssid_chunks"].get(s, 0) + 1
        self.ctx["n_chunks"] += 1
        self.ctx["pairs"] = sorted(set(map(tuple, self.ctx["pairs"])) | self.chunk_pairs)
        self.chunk_pairs, self.chunk_ssids = set(), set()
        self._save_ctx()

    def _watchdog(self, silent_for):
        """The RTL88x2bu has dropped out of monitor mode on its own before."""
        if silent_for < 30 or self.replay is not None:
            return
        self._log(f"no frames for {silent_for:.0f}s — re-preparing {self.iface}")
        try:
            self.sniffer.stop()
        except Exception:
            pass
        ok, msg = self._prepare(self.iface, self.channel, self.width)
        if ok:
            self._start_sniffer()
            self.restarts += 1
        else:
            self.error = msg
        with self.lock:
            self.last_frame_at = time.time()

    # ---------------------------------------------------------------- learning
    def _protected(self):
        n = max(self.ctx["n_chunks"], 1)
        return {s for s, c in self.ctx["ssid_chunks"].items() if c >= 0.9 * n}

    def _known_pairs(self):
        prot = self._protected()
        return {(s, b) for s, b in map(tuple, self.ctx["pairs"]) if s in prot}

    def _arp_seed(self):
        return pd.DataFrame(list(self.ctx["arp"].items()), columns=["arp.src.proto_ipv4", "arp.src.hw_mac"])

    def _train_table(self):
        if self.features.empty:
            return None
        f = self.features
        # Anti-poisoning: never learn seconds (±5 s) that a RULE flagged, or that
        # the model flagged once it was trusted (Brain Power ≥ 50). Model-only
        # alerts from the learning phase don't count: while the model is still
        # noisy they would cover almost every second and nothing would ever be
        # learned (what happened live on 2026-10-08: 159 alerts in 25 min).
        # On top of that, only the seconds the training policy selects.
        f = f[self.train_mask(f["win"].astype("int64").to_numpy())]
        if f.empty:
            return None
        feats = [c for c in f.columns if c not in ("win", "file", "a_score", "a_alert", "b_alert")]
        return f[feats].astype("float32")

    # ------------------------------------------------------- training data
    def _poison_intervals(self):
        """Seconds (±5 s) a rule or a trusted model A flagged — never learned."""
        return _intervals((a["start"] - 5, a["end"] + 5) for a in self._read_alerts()
                          if a.get("confidence") in ("rule", "normal"))

    def _policy_mask(self, wins, now=None):
        """Which seconds the training policy selects (mode + excluded periods)."""
        pol, now = self.ctx["train_policy"], now or time.time()
        if pol["mode"] == "roll":
            mask = wins >= now - pol["days"] * 86400
        elif pol["mode"] == "pick":
            days = set(pol["chosen"])
            local = wins - time.timezone
            uniq, inv = np.unique(local // 86400, return_inverse=True)
            mask = np.array([_local_day(d * 86400 + time.timezone) in days for d in uniq], dtype=bool)[inv] \
                if len(uniq) else np.zeros(0, dtype=bool)
        else:
            mask = np.ones(len(wins), dtype=bool)
        ex = _intervals((e["start"], e["end"]) for e in pol["excludes"])
        return mask & ~_in_intervals(wins, ex)

    def train_mask(self, wins):
        return self._policy_mask(wins) & ~_in_intervals(wins, self._poison_intervals())

    def _selected_slots(self):
        """Hour-of-week second counts of the policy-selected data (Brain
        Power coverage). Cached per 10 min / data size / policy."""
        key = (self.n_feat_rows, json.dumps(self.ctx["train_policy"], sort_keys=True), int(time.time() // 600))
        if self._sel_cache[0] == key:
            return self._sel_cache[1]
        grid = np.zeros((7, 24))
        if not self.features.empty:
            w = self.features["win"].astype("int64").to_numpy()
            local = w[self._policy_mask(w)] - time.timezone
            np.add.at(grid, (((local // 86400) + 3) % 7, (local % 86400) // 3600), 1)
        self._sel_cache = (key, grid)
        return grid

    def paused(self):
        until = self.ctx["train_policy"].get("pause_until")
        return bool(until and until > time.time())

    def set_pause(self, hours):
        """hours > 0: stop learning for that long (detection keeps running);
        0: resume now. A pause is also an excluded period, so the seconds
        collected meanwhile are never trained on later either."""
        pol, now = self.ctx["train_policy"], time.time()
        for e in pol["excludes"]:
            if e.get("auto") and e["end"] > now:
                e["end"] = int(now)             # close a running pause
        # a pause undone within a minute excluded nothing worth listing
        pol["excludes"] = [e for e in pol["excludes"] if not (e.get("auto") and e["end"] - e["start"] < 60)]
        if hours > 0:
            until = int(now + hours * 3600)
            pol["pause_until"] = until
            pol["excludes"].append({"start": int(now), "end": until, "reason": "learning paused", "auto": True})
            self._log(f"learning paused until {time.strftime('%d %b %H:%M', time.localtime(until))}")
        else:
            pol["pause_until"] = None
            self._log("learning resumed")
        self._save_ctx()

    def set_training_policy(self, data):
        """Validate and save the Training data card's settings, then retrain.
        Return (ok, message)."""
        pol = dict(self.ctx["train_policy"])
        mode = data.get("mode", pol["mode"])
        if mode not in ("roll", "pick", "all"):
            return False, "mode must be roll, pick or all"
        try:
            days = int(data.get("days", pol["days"]))
            raw = {"enabled": bool(data.get("raw_retention", pol["raw_retention"])["enabled"]),
                   "days": int(data.get("raw_retention", pol["raw_retention"])["days"])}
            feat = {"enabled": bool(data.get("feat_retention", pol["feat_retention"])["enabled"]),
                    "days": int(data.get("feat_retention", pol["feat_retention"])["days"])}
            excludes = [{"start": int(e["start"]), "end": int(e["end"]), "reason": str(e.get("reason", ""))[:80],
                         **({"auto": True} if e.get("auto") else {})}
                        for e in data.get("excludes", pol["excludes"])]
        except (TypeError, ValueError, KeyError):
            return False, "days and periods must be numbers"
        chosen = sorted({str(d) for d in data.get("chosen", pol["chosen"])})
        if days < MIN_TRAIN_DAYS:
            return False, f"use at least {MIN_TRAIN_DAYS} days (one full week)"
        if mode == "pick" and not chosen:
            return False, "choose at least one day"
        if any(e["end"] < e["start"] for e in excludes):
            return False, "an excluded period ends before it starts"
        if raw["days"] < MIN_TRAIN_DAYS:
            return False, f"keep raw frames at least {MIN_TRAIN_DAYS} days"
        if feat["enabled"]:
            need = days if mode == "roll" else MIN_TRAIN_DAYS
            if mode == "pick" and chosen:
                oldest = time.mktime(time.strptime(chosen[0], "%Y-%m-%d"))
                need = max(need, int((time.time() - oldest) // 86400) + 1)
            if feat["days"] < need:
                return False, f"per-second features are the training data: keep them at least {need} days"
        pol.update(mode=mode, days=days, chosen=chosen, excludes=excludes, raw_retention=raw, feat_retention=feat)
        self.ctx["train_policy"] = pol
        self._save_ctx()
        self._log(f"training data set to {self._policy_text()}")
        if self.running:
            self._retrain_requested = True      # picked up by the next tick (≤ 5 s)
        else:
            self._retrain()
        return True, "ok"

    def _policy_text(self):
        pol = self.ctx["train_policy"]
        return {"roll": f"last {pol['days']} days", "all": "all data",
                "pick": f"{len(pol['chosen'])} chosen days"}[pol["mode"]]

    def _cleanup(self, now, dry_run=False):
        """Apply the retention settings. Return what was (or would be) deleted."""
        pol = self.ctx["train_policy"]
        out = {"raw_files": 0, "raw_bytes": 0, "feature_rows": 0}
        if pol["raw_retention"]["enabled"]:
            cutoff = now - pol["raw_retention"]["days"] * 86400
            current = self.writer.path if self.running else None
            for e in os.scandir(self.raw_dir):
                if not (e.name.startswith("capture_") and e.name.endswith(".csv.gz")) or e.path == current:
                    continue
                try:
                    t = time.mktime(time.strptime(e.name[8:23], "%Y%m%d_%H%M%S"))
                except ValueError:
                    continue
                if t < cutoff:
                    out["raw_files"] += 1
                    out["raw_bytes"] += e.stat().st_size
                    if not dry_run:
                        os.remove(e.path)
                        side = e.path[:-7] + ".json"
                        if os.path.exists(side):
                            os.remove(side)
        if pol["feat_retention"]["enabled"] and not self.features.empty:
            cutoff = now - pol["feat_retention"]["days"] * 86400
            old = self.features["win"].astype("int64") < cutoff
            out["feature_rows"] = int(old.sum())
            if out["feature_rows"] and not dry_run:
                keep = self.features[~old]
                tmp = self.feat_path + ".tmp"
                keep.to_csv(tmp, index=False)
                os.replace(tmp, self.feat_path)
                self._feat_parts, self._feat_cache = [], None
                self.slot_counts, self.n_feat_rows = np.zeros((7, 24)), 0
                self._remember(keep.reset_index(drop=True))
        return out

    def _daily_cleanup(self, now):
        today = _local_day(now)
        if time.localtime(now).tm_hour < CLEANUP_HOUR or self.ctx.get("last_cleanup", {}).get("day") == today:
            return
        res = self._cleanup(now)
        self.ctx["last_cleanup"] = {"day": today, "time": now, **res}
        self._save_ctx()
        if res["raw_files"] or res["feature_rows"]:
            self._log(f"cleanup: deleted {res['raw_files']} raw files ({res['raw_bytes'] / 1e9:.2f} GB)"
                      f", {res['feature_rows']:,} feature rows")

    def training_info(self):
        """Everything the Training data card shows."""
        now = time.time()
        f = self.features
        days = []
        sel_secs = 0
        if not f.empty:
            w = f["win"].astype("int64").to_numpy()
            pol_mask = self._policy_mask(w, now)
            bad = _in_intervals(w, self._poison_intervals())
            local = w - time.timezone
            dnum, hour = local // 86400, (local % 86400) // 3600
            sel_secs = int((pol_mask & ~bad).sum())
            for d in np.unique(dnum):
                m = dnum == d
                days.append({
                    "date": _local_day(d * 86400 + time.timezone),
                    "weekday": int((d + 3) % 7),            # 0 = Monday, as in coverage_grid
                    "hour_secs": np.bincount(hour[m], minlength=24).astype(int).tolist(),
                    "seconds": int(m.sum()), "flagged": int((m & bad).sum()),
                    "selected": int((m & pol_mask).sum()),
                })
        raw = [e for e in os.scandir(self.raw_dir) if e.name.endswith(".csv.gz")]
        return {
            "policy": self.ctx["train_policy"], "policy_text": self._policy_text(),
            "paused": self.paused(), "now": now, "min_days": MIN_TRAIN_DAYS,
            "days": days, "selected_seconds": sel_secs,
            "coverage": round(100 * float(np.clip(self._selected_slots() / SLOT_TARGET, 0, 1).mean()), 1),
            "trained_on": self.detector.n_train if self.detector else 0,
            "raw": {"files": len(raw), "bytes": sum(e.stat().st_size for e in raw)},
            "features_bytes": os.path.getsize(self.feat_path) if os.path.exists(self.feat_path) else 0,
            "would_delete": self._cleanup(now, dry_run=True),
            "last_cleanup": self.ctx.get("last_cleanup"), "cleanup_hour": CLEANUP_HOUR,
        }

    def _retrain(self):
        self.last_retrain = time.time()
        X = self._train_table()
        if X is None or len(X) < MIN_TRAIN_WINDOWS:
            return
        self._record_unseen_interval()
        self._update_trust()
        det = Detector(X)
        self.ctx["last_fit"] = self.last_retrain
        with self.lock:
            self.detector, self.feats = det, list(X.columns)
        hist = self.ctx["retrains"]
        # Brain Power only learns something from a refit on meaningfully MORE
        # data (≥10 %): refitting the same baseline (e.g. after an app restart)
        # is trivially "stable" and would inflate it.
        if hist and len(X) < 1.1 * hist[-1]["n_train"]:
            return
        fa = self._fa_rate()
        limits = det.raw_limits()
        stability = None
        if hist:
            prev = pd.Series(hist[-1]["limits"])
            common = limits.index.intersection(prev.index)
            rel = ((limits[common] - prev[common]).abs() / prev[common].abs().clip(lower=1e-6)).median()
            stability = float(np.clip(1 - rel * 5, 0, 1))    # 20 % median shift -> 0
        hist.append({"time": self.last_retrain, "n_train": len(X), "limits": limits.round(6).to_dict(),
                     "stability": stability, "fa_events_per_hour": fa})
        self.ctx["retrains"] = hist[-50:]
        self._save_ctx()
        self._log(f"retrained on {len(X):,} clean seconds"
                  + (f"; FA on unseen data {fa:.1f}/h" if fa is not None else ""))

    def _record_unseen_interval(self):
        """Seconds judged since the previous refit were scored by a model that
        was fitted BEFORE they existed — truly unseen data. Record how many
        alarms it raised on them (info notices aren't alarms)."""
        since = self.ctx.get("last_fit")
        if since is None or self.features.empty:
            return
        seconds = int((self.features["win"] > since).sum())
        if seconds == 0:
            return
        # Not counted: info notices (not alarms) and A+B (both detectors agree,
        # more likely a real event than noise).
        events = sum(1 for a in self._read_alerts()
                     if a["start"] > since and a.get("confidence") != "info" and a["detector"] != "A+B")
        iv = self.ctx.setdefault("unseen", [])
        iv.append({"start": since, "end": self.last_retrain, "seconds": seconds, "events": events})
        cutoff = self.last_retrain - 7 * 86400
        self.ctx["unseen"] = [x for x in iv if x["end"] >= cutoff]

    def _fa_rate(self):
        """Alarms/hour on unseen data: the MEDIAN of the hourly rates over the
        last FA_HORIZON (hours with ≥ 5 min of data). A median, so an attack
        concentrated in an hour or two doesn't read as a noisy model, while a
        model that is noisy every hour still scores badly."""
        now = time.time()
        hours = {}
        for x in self.ctx.get("unseen", []):
            if x["end"] >= now - FA_HORIZON:
                h = hours.setdefault(int(x["end"] // 3600), [0, 0])
                h[0] += x["events"]
                h[1] += x["seconds"]
        rates = [ev / (sec / 3600) for ev, sec in hours.values() if sec >= 300]
        self._fa_hours = len(rates)
        return float(np.median(rates)) if rates else None

    def _update_trust(self):
        """Hysteresis for model A's trust (see TRUST_* above)."""
        bp, fa, now = self.brain()["power"], self._fa_rate(), time.time()
        ok = bp >= TRUST_BP and fa is not None and fa <= TRUST_FA and self._fa_hours >= MIN_FA_HOURS
        if ok:
            self.ctx.pop("distrust_since", None)
            if not self.ctx.get("a_trusted"):
                self.ctx["a_trusted"] = True
                self._log(f"model A now trusted (Brain Power {bp}%, FA {fa:.1f}/h)")
        elif self.ctx.get("a_trusted"):
            since = self.ctx.setdefault("distrust_since", now)
            if now - since >= DISTRUST_AFTER:
                self.ctx["a_trusted"] = False
                self.ctx.pop("distrust_since", None)
                self._log("model A back to learning mode (criteria failed for 24 h)")

    def brain(self):
        cov_grid = np.clip(self._selected_slots() / SLOT_TARGET, 0, 1)
        coverage = float(cov_grid.mean())
        stabs = [r["stability"] for r in self.ctx["retrains"] if r.get("stability") is not None][-3:]
        stability = float(np.mean(stabs)) if stabs else 0.0
        fa = self._fa_rate()
        if fa is None:
            fa_score = 0.0
        elif fa <= FA_TARGET:
            fa_score = 1.0
        else:
            fa_score = float(np.clip(1 - math.log(fa / FA_TARGET) / math.log(FA_WORST / FA_TARGET), 0, 1))
        power = round(100 * (0.5 * coverage + 0.25 * stability + 0.25 * fa_score), 1)
        level = ("Learning" if power < 30 else "Calibrating" if power < 70
                 else "Almost ready" if power < 95 else "Ready")
        return {
            "power": power, "level": level,
            "coverage": round(100 * coverage, 1), "stability": round(100 * stability, 1),
            "fa_score": round(100 * fa_score, 1), "fa_events_per_hour": fa,
            "coverage_grid": cov_grid.round(3).tolist(),
            "hours_of_data": round(self.n_feat_rows / 3600, 2),
            "train_windows": self.detector.n_train if self.detector else 0,
            "retrains": len(self.ctx["retrains"]),
            "last_retrain": self.ctx["retrains"][-1]["time"] if self.ctx["retrains"] else None,
            "next_retrain_in": max(0, int(RETRAIN_EVERY - (time.time() - self.last_retrain))) if self.running else None,
            "protected_ssids": sorted(self._protected()),
            "a_trusted": bool(self.ctx.get("a_trusted")),
            "fa_hours_measured": getattr(self, "_fa_hours", 0),
            "a_distrust_since": self.ctx.get("distrust_since"),
            "train_policy": self._policy_text(), "learning_paused": self.paused(),
        }

    # ------------------------------------------------------------- import
    @staticmethod
    def _file_features(path):
        df = load(path)
        f, pairs = windows(df, 1)
        f = f.iloc[1:-1].drop(columns=["file"])      # partial first/last second
        f.insert(0, "win", f.index)
        f["a_score"], f["a_alert"], f["b_alert"] = np.nan, False, False
        return f, df, pairs

    def _rebuild_features(self):
        """Recompute the per-second table from every raw capture it came from
        (imported baselines + the monitor's own raw/ chunks) with the current
        feature code. Model scores/flags of past seconds are not recomputed —
        training exclusions come from alerts.jsonl instead."""
        captures = os.path.dirname(self.dir)
        sources = [os.path.join(captures, k) for k in self.ctx["imported"]]
        sources += [os.path.join(self.raw_dir, p) for p in sorted(os.listdir(self.raw_dir))
                    if p.endswith((".csv", ".csv.gz"))]
        parts = []
        for p in sources:
            if os.path.exists(p):
                try:
                    parts.append(self._file_features(p)[0])
                except Exception as e:
                    self._log(f"rebuild: skipped {os.path.basename(p)} ({e})")
        if os.path.exists(self.feat_path):
            os.replace(self.feat_path, self.feat_path + ".v%s.bak" % self.ctx.get("feature_version", 1))
        if parts:
            table = pd.concat(parts, ignore_index=True).sort_values("win").drop_duplicates("win")
            table.to_csv(self.feat_path, index=False)
            self._remember(table)
        self.ctx["feature_version"] = FEATURE_VERSION
        self._save_ctx()
        self._log(f"rebuilt features v{FEATURE_VERSION} from {len(parts)} raw files ({self.n_feat_rows:,} s)")

    def _read_alerts(self):
        if not os.path.exists(self.alert_path):
            return []
        with open(self.alert_path, encoding="utf-8", errors="ignore") as f:
            # NUL-padded / half-written last line after a power loss is skipped
            return [json.loads(l) for l in f if l.startswith("{") and l.rstrip().endswith("}")]

    def import_baselines(self, dirs):
        """Seed the baseline from earlier captures (same channel/width!)."""
        added = 0
        for d in dirs:
            for p in sorted(os.listdir(d)):
                if not (p.endswith(".csv") or p.endswith(".csv.gz")):
                    continue
                key = os.path.join(os.path.basename(d), p)
                if key in self.ctx["imported"]:
                    continue
                f, df, pairs = self._file_features(os.path.join(d, p))
                self._append_features(f)
                bcn = df[(df["wlan.fc.type"] == 0) & (df["wlan.fc.subtype"] == 8)]
                for s in bcn["wlan.ssid"].dropna().unique():
                    self.ctx["ssid_chunks"][s] = self.ctx["ssid_chunks"].get(s, 0) + 1
                self.ctx["n_chunks"] += 1
                self.ctx["pairs"] = sorted(set(map(tuple, self.ctx["pairs"])) | pairs)
                a = df.dropna(subset=["arp.src.proto_ipv4", "arp.src.hw_mac"])
                self.ctx["arp"].update(dict(zip(a["arp.src.proto_ipv4"], a["arp.src.hw_mac"])))
                self.ctx["imported"].append(key)
                added += 1
        self._save_ctx()
        if added:
            self._retrain()
        self._log(f"imported {added} baseline files")
        return added

    # ------------------------------------------------------------- reporting
    def _build_snapshot(self, df, now):
        f = pd.concat(self._feat_parts[-200:], ignore_index=True).tail(600) if self._feat_parts else pd.DataFrame()
        series = {}
        if not f.empty:
            series = {k: f[k].round(3).tolist() for k in ("win", "frames", "mgmt", "ctrl", "data", "deauth")
                      if k in f}
            if "a_score" in f:
                series["a_score"] = f["a_score"].round(4).tolist()
        last60 = f.tail(60)
        kpi = {}
        if not last60.empty:
            kpi = {
                "frames_per_s": round(float(last60["frames"].mean()), 1),
                "data_per_s": round(float(last60["data"].mean()), 1),
                "encrypted_pct": round(100 * float(last60["protected_ratio"].mean()), 1),
                "retry_pct": round(100 * float(last60["retry_ratio"].mean()), 1),
                "signal_dbm": round(float(last60["signal_mean"].mean()), 1),
            }
        aps, n_tx = [], 0
        if not df.empty:
            recent = df[df["frame.time_epoch"] >= now - 60]
            n_tx = int(recent["wlan.ta"].nunique())
            b = recent[(recent["wlan.fc.type"] == 0) & (recent["wlan.fc.subtype"] == 8)]
            known, prot = self._known_pairs(), self._protected()
            for bssid, g in b.groupby("wlan.bssid"):
                ssid = g["wlan.ssid"].dropna()
                ssid = ssid.iloc[0] if len(ssid) else ""
                aps.append({"bssid": bssid, "ssid": ssid,
                            "signal": round(float(g["wlan_radio.signal_dbm"].median()), 1),
                            "beacons_per_s": round(len(g) / 60, 1),
                            "protected": ssid in prot, "known": (ssid, bssid) in known})
            aps.sort(key=lambda a: (not a["protected"], -a["signal"]))
        kpi["transmitters_last_min"] = n_tx
        prot = self._protected()
        dfs_warning = bool(prot) and self.running and not any(a["protected"] for a in aps) and now - self.started_at > 120
        hour_ago = time.time() - 3600
        snap = {
            "running": self.running, "iface": self.iface, "channel": self.channel, "width": self.width,
            "uptime_s": int(now - self.started_at) if self.running else 0,
            "frames_total": getattr(self, "frames_total", 0), "restarts": getattr(self, "restarts", 0),
            "raw_file": os.path.basename(self.writer.path) if self.running and self.writer.path else None,
            "raw_dir_mb": round(sum(e.stat().st_size for e in os.scandir(self.raw_dir)) / 1e6, 1),
            "disk_free_gb": round(shutil.disk_usage(self.dir).free / 1e9, 1),
            "error": self.error, "dfs_warning": dfs_warning,
            "kpi": kpi, "series": series, "aps": aps[:30],
            "alerts": list(reversed(self.alerts[-50:])),
            "alerts_last_hour": sum(1 for a in self.alerts if a["start"] >= hour_ago and a.get("confidence") != "info"),
            "notices_last_hour": sum(1 for a in self.alerts if a["start"] >= hour_ago and a.get("confidence") == "info"),
            "alerts_by_type_24h": self._alert_counts(time.time() - 86400),
            "brain": self.brain(), "log": list(self.log)[-15:],
            "model_ready": self.detector is not None,
            "model_c": self.model_c.status(),
            "pending_aps": sorted(({"bssid": b, **p} for b, p in self.ctx.get("pending_aps", {}).items()),
                                  key=lambda x: -x.get("last_seen", 0)),
            "detector": self._detector_summary(),
        }
        self.snapshot = _jsonable(snap)

    def _detector_summary(self):
        d = self.detector
        if d is None:
            return None
        from analysis.detector import FLOOD_FLOOR
        return {"a_threshold": d.thr,
                "single_occurrence": [{"feature": f, "meaning": HINTS.get(f, f)} for f in d.never_seen],
                "flood_limits": [{"feature": f, "limit": round(d.flood_limit(f), 2), "meaning": HINTS.get(f, f)}
                                 for f in FLOOD_FLOOR if f in d.feats and f not in d.never_seen]}

    def _alert_counts(self, since):
        """{type: {"A": n, "B": n, "A+B": n, "total": n}}, most frequent first."""
        c = {}
        for a in self.alerts:
            if a["start"] >= since:
                for t in a["types"]:
                    row = c.setdefault(t, {"A": 0, "B": 0, "A+B": 0, "total": 0})
                    row[a["detector"]] += 1
                    row["total"] += 1
        return dict(sorted(c.items(), key=lambda kv: -kv[1]["total"]))

    def status(self):
        if not self.running:
            self._build_snapshot(pd.DataFrame(), time.time())
        return self.snapshot

    def _save_ctx(self):
        tmp = self.ctx_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.ctx, f)
        os.replace(tmp, self.ctx_path)

    def _log(self, msg):
        self.log.append(f"{time.strftime('%H:%M:%S')} {msg}")
