"""
WiFi Packet Capture POC — Flask backend.

Run:
    sudo python3 app.py                 # real capture (needs monitor-mode iface + root)

Then open http://<this-machine-lan-ip>:5000 from any browser on the LAN.

See wifi_capture_poc_spec.md for the full spec this implements.
"""

import logging
import os

from flask import Flask, jsonify, render_template, request, send_file, abort

from capture import FIELD_ATTACKS, PROFILES, start_capture, set_monitor_mode

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CAPTURES_DIR = os.path.join(BASE_DIR, "captures")

app = Flask(__name__)

# In-memory registry of capture sessions (POC only — not persisted across restarts)
SESSIONS = {}

DEFAULT_DURATION = 15   # seconds
DEFAULT_MAX_PACKETS = 200


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/prepare-interface", methods=["POST"])
def prepare_interface():
    """Down -> monitor mode -> up, so the user only has to type the
    interface name and click a button instead of running three commands
    in a terminal. Needs the same root/CAP_NET_ADMIN this app already
    requires for a real capture."""
    data = request.get_json(silent=True) or {}
    interface = (data.get("interface") or "").strip()
    if not interface:
        return jsonify({"error": "Interface name is required."}), 400

    ok, message = set_monitor_mode(interface)
    if not ok:
        return jsonify({"error": message}), 400
    return jsonify({"ok": True})


# ---------------------------------------------------------------- live monitor
_monitor = None


def get_monitor():
    """Created on first use: it loads pandas/scikit-learn and refits the
    detectors from captures/monitor/, which takes a few seconds."""
    global _monitor
    if _monitor is None:
        from monitor import LiveMonitor
        _monitor = LiveMonitor(os.path.join(CAPTURES_DIR, "monitor"))
    return _monitor


@app.route("/monitor")
def monitor_page():
    return render_template("monitor.html")


@app.route("/api/monitor/status")
def monitor_status():
    return jsonify(get_monitor().status())


@app.route("/api/monitor/start", methods=["POST"])
def monitor_start():
    data = request.get_json(silent=True) or {}
    replay = data.get("replay") or None
    if replay:
        replay = os.path.normpath(os.path.join(os.path.abspath(CAPTURES_DIR), replay))
        if not replay.startswith(os.path.abspath(CAPTURES_DIR) + os.sep):
            return jsonify({"error": "replay file must be inside captures/"}), 400
    ok, msg = get_monitor().start((data.get("interface") or "").strip(), str(data.get("channel") or "100"),
                                  (data.get("width") or "").strip(), replay=replay)
    return (jsonify({"ok": True}), 200) if ok else (jsonify({"error": msg}), 400)


@app.route("/api/monitor/stop", methods=["POST"])
def monitor_stop():
    get_monitor().stop(remember=False)
    return jsonify({"ok": True})


@app.route("/api/monitor/approve_ap", methods=["POST"])
def monitor_approve_ap():
    bssids = (request.get_json(silent=True) or {}).get("bssids") or []
    return jsonify({"ok": True, "approved": get_monitor().approve_aps([str(b) for b in bssids])})


@app.route("/api/monitor/training", methods=["GET", "POST"])
def monitor_training():
    """Training data card: which seconds A/B train on, and data retention."""
    mon = get_monitor()
    if request.method == "POST":
        ok, msg = mon.set_training_policy(request.get_json(silent=True) or {})
        if not ok:
            return jsonify({"error": msg}), 400
    return jsonify(mon.training_info())


@app.route("/api/monitor/training/pause", methods=["POST"])
def monitor_training_pause():
    """{"hours": n} pauses learning for n hours; {"hours": 0} resumes."""
    try:
        hours = float((request.get_json(silent=True) or {}).get("hours", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "hours must be a number"}), 400
    if not 0 <= hours <= 72:
        return jsonify({"error": "pause for at most 72 hours"}), 400
    get_monitor().set_pause(hours)
    return jsonify(get_monitor().training_info())


@app.route("/api/monitor/baselines")
def monitor_baselines():
    """Earlier capture folders that can seed the baseline, and recorded files
    that can be replayed."""
    dirs, files = [], []
    for d in sorted(os.listdir(CAPTURES_DIR)) if os.path.isdir(CAPTURES_DIR) else []:
        full = os.path.join(CAPTURES_DIR, d)
        if d == "monitor" or not os.path.isdir(full):
            continue
        caps = sorted(f for f in os.listdir(full) if f.endswith((".csv", ".csv.gz")))
        if caps:
            dirs.append({"name": d, "files": len(caps), "imported": sum(
                os.path.join(d, f) in get_monitor().ctx["imported"] for f in caps)})
            files += [os.path.join(d, f) for f in caps]
    return jsonify({"dirs": dirs, "replay_files": files})


@app.route("/api/monitor/import", methods=["POST"])
def monitor_import():
    names = (request.get_json(silent=True) or {}).get("dirs") or []
    dirs = [os.path.join(CAPTURES_DIR, n) for n in names
            if n != "monitor" and os.path.isdir(os.path.join(CAPTURES_DIR, n)) and os.sep not in n]
    added = get_monitor().import_baselines(dirs)
    return jsonify({"ok": True, "imported_files": added})


@app.route("/capture", methods=["POST"])
def capture():
    data = request.get_json(silent=True) or {}
    interface = (data.get("interface") or "wlan1mon").strip()
    simulate = bool(data.get("simulate", False))
    llc_snap_dispatch = bool(data.get("llc_snap_dispatch", False))
    compress = bool(data.get("compress", False))
    # channel to tune to before capturing; empty = keep the adapter's current one
    channel = str(data.get("channel") or "").strip() or None
    width = str(data.get("width") or "").strip() or None
    if channel is not None and not channel.isdigit():
        return jsonify({"error": "Channel must be a number."}), 400
    if width not in (None, "HT20", "HT40+", "HT40-", "80MHz"):
        return jsonify({"error": "Width must be HT20, HT40+, HT40- or 80MHz."}), 400
    profile = data.get("profile") or "default"
    if profile not in PROFILES:
        return jsonify({"error": f"Profile must be one of {', '.join(PROFILES)}."}), 400
    experiment = str(data.get("experiment") or "").strip()[:120]
    if profile == "field":
        # fixed settings for field experiments (see capture.PROFILES)
        if channel is None and not simulate:
            return jsonify({"error": "Field captures need the channel set, so it can be checked and recorded."}), 400
        compress, llc_snap_dispatch, max_packets = True, True, None

    raw_duration = data.get("duration", DEFAULT_DURATION)
    duration = int(raw_duration) if raw_duration not in (None, "") else None

    raw_max_packets = data.get("max_packets", DEFAULT_MAX_PACKETS)
    max_packets = int(raw_max_packets) if raw_max_packets not in (None, "") else None

    if not interface:
        return jsonify({"error": "Interface name is required."}), 400

    if not simulate and _monitor is not None and _monitor.running and _monitor.iface == interface:
        return jsonify({"error": f"The live monitor is using {interface} — stop it on the Monitor page first."}), 409

    if duration is None and max_packets is None and profile == "default":
        return jsonify({"error": "Choose at least one stop condition: time, packet count, or both."}), 400

    session = start_capture(interface, simulate, duration, max_packets, CAPTURES_DIR,
                             llc_snap_dispatch=llc_snap_dispatch, compress=compress,
                             channel=channel, width=width, profile=profile, experiment=experiment)
    SESSIONS[session.id] = session
    return jsonify({"capture_id": session.id})


@app.route("/stop/<capture_id>", methods=["POST"])
def stop(capture_id):
    session = SESSIONS.get(capture_id)
    if session is None:
        abort(404, description="Unknown capture_id")
    session.request_stop()
    return jsonify({"stopping": True})


@app.route("/status/<capture_id>")
def status(capture_id):
    session = SESSIONS.get(capture_id)
    if session is None:
        abort(404, description="Unknown capture_id")
    return jsonify(session.to_dict())


@app.route("/capture/<capture_id>/ground_truth", methods=["POST"])
def ground_truth(capture_id):
    """Field captures: mark attack periods. Body: {"action": "start"|"end"|
    "add"|"delete", "attack", "pmf": "on"|"off"|"unknown", "notes",
    "start", "end" (unix s, for "add"), "index" (for "delete")}."""
    session = SESSIONS.get(capture_id)
    if session is None:
        abort(404, description="Unknown capture_id")
    d = request.get_json(silent=True) or {}
    ok, msg = session.mark(d.get("action"), attack=d.get("attack"), pmf=d.get("pmf"), notes=d.get("notes") or "",
                           start=d.get("start"), end=d.get("end"), index=d.get("index"))
    if not ok:
        return jsonify({"error": msg}), 400
    return jsonify(session.to_dict())


@app.route("/capture/attacks")
def capture_attacks():
    return jsonify({"attacks": FIELD_ATTACKS})


@app.route("/download/<capture_id>")
def download(capture_id):
    """?file=csv (default) | ground_truth | sidecar"""
    session = SESSIONS.get(capture_id)
    if session is None:
        abort(404, description="Unknown capture_id")
    if session.status != "done" or not session.csv_path:
        abort(409, description="Capture is not finished yet.")
    which = request.args.get("file", "csv")
    if which == "ground_truth" and session.gt_path:
        return send_file(session.gt_path, as_attachment=True)
    if which == "sidecar":
        from capture import sidecar_path
        return send_file(sidecar_path(session.csv_path), as_attachment=True)
    return send_file(session.csv_path, as_attachment=True)


class _QuietStatusPolling(logging.Filter):
    """The dashboard polls /api/monitor/status every 2 s; under systemd that
    would be ~43k access-log lines a day in the journal."""

    def filter(self, record):
        return "/api/monitor/status" not in record.getMessage()


if __name__ == "__main__":
    logging.getLogger("werkzeug").addFilter(_QuietStatusPolling())
    os.makedirs(CAPTURES_DIR, exist_ok=True)
    # If the monitor was running when the app last went down (crash, service
    # restart, reboot), pick it up again — the point is unattended collection.
    if os.path.exists(os.path.join(CAPTURES_DIR, "monitor", "context.json")):
        get_monitor().resume()
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
