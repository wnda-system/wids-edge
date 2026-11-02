"""Collect a baseline for anomaly detection: fixed channel + width, written as
fixed-length chunks (CaptureSession buffers a whole capture in RAM, so one
long capture would run out of memory). Meant to run unattended for days.
Ctrl-C any time — finished chunks are kept.

    sudo ../venv/bin/python3 collect_baseline.py --chunks 0          # until stopped
    sudo ../venv/bin/python3 collect_baseline.py --hours 24 --out baseline_24h

Defaults match the setup in anomaly_detection_notes.md: channel 100 HT40+,
5-minute gzip chunks (~44 MB/h on channel 100), LLC/SNAP dispatch on.
"""
import argparse, os, shutil, subprocess, sys, time, uuid

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP_DIR)
from capture import CaptureSession, check_monitor_mode, set_monitor_mode

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--iface", default="wlx1cbfce71ebe7")
ap.add_argument("--channel", default="100")
ap.add_argument("--width", default="HT40+", help="iw width arg (HT20, HT40+, HT40-, or '' for no-HT)")
ap.add_argument("--chunk", type=int, default=300, help="seconds per file")
ap.add_argument("--chunks", type=int, default=None, help="number of files, 0 = until stopped")
ap.add_argument("--hours", type=float, default=None, help="alternative to --chunks")
ap.add_argument("--out", default="baseline_ch100_ht40_gz", help="subfolder of captures/")
ap.add_argument("--no-compress", action="store_true", help="write plain .csv (~10x bigger)")
ap.add_argument("--min-free-gb", type=float, default=5.0, help="stop before the disk gets this full")
args = ap.parse_args()

if args.chunks is None:
    args.chunks = int(args.hours * 3600 // args.chunk) if args.hours else 12
OUT = os.path.join(APP_DIR, "captures", args.out)
os.makedirs(OUT, exist_ok=True)
CHANNEL_ARGS = ["set", "channel", args.channel] + ([args.width] if args.width else [])


def channel_line():
    info = subprocess.run(["iw", "dev", args.iface, "info"], capture_output=True, text=True).stdout
    return next((l.strip() for l in info.splitlines() if l.strip().startswith("channel")), "?")


def prepare():
    """Re-assert monitor mode + channel every chunk: the RTL88x2bu has dropped
    back to managed/DOWN on its own before."""
    ok, msg = check_monitor_mode(args.iface)
    if not ok:
        print(f"    not in monitor mode ({msg}) — re-enabling", flush=True)
        ok, msg = set_monitor_mode(args.iface)
        if not ok:
            return False, f"could not enable monitor mode: {msg}"
    r = subprocess.run(["iw", "dev", args.iface] + CHANNEL_ARGS, capture_output=True, text=True)
    if r.returncode != 0:
        return False, f"could not set channel: {r.stderr.strip()}"
    return True, "ok"


total = "∞" if args.chunks == 0 else str(args.chunks)
print(f"Collecting {total} × {args.chunk}s on ch{args.channel} {args.width or 'no-HT'} "
      f"-> {OUT} ({'csv' if args.no_compress else 'csv.gz'})", flush=True)
i, failures = 0, 0
while args.chunks == 0 or i < args.chunks:
    free_gb = shutil.disk_usage(OUT).free / 1e9
    if free_gb < args.min_free_gb:
        print(f"stopping: only {free_gb:.1f} GB free (--min-free-gb {args.min_free_gb})", flush=True)
        break
    ok, msg = prepare()
    if ok:
        time.sleep(1.0)
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] chunk {i + 1}/{total} — {channel_line()}", flush=True)
        s = CaptureSession(str(uuid.uuid4()), args.iface, False, args.chunk, None, OUT,
                           llc_snap_dispatch=True, compress=not args.no_compress)
        s.run()
        d = s.to_dict()
        ok, msg = d["status"] == "done", d["error"]
        print(f"    {d['status']}: {d['packets_captured']:,} frames -> {d['csv_filename']}", flush=True)
    if ok:
        i, failures = i + 1, 0
        continue
    # Unattended runs: a transient driver hiccup shouldn't end a week-long
    # collection, but a persistent failure shouldn't spin forever either.
    failures += 1
    print(f"    ERROR ({failures}/5): {msg}", flush=True)
    if failures >= 5:
        print("stopping after 5 consecutive failures", flush=True)
        break
    time.sleep(10)
print("done. files in", OUT)
