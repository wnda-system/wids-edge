"""
WiFi Packet Capture POC — Flask backend.

Run:
    sudo python3 app.py                 # real capture (needs monitor-mode iface + root)

Then open http://<this-machine-lan-ip>:5000 from any browser on the LAN.

See wifi_capture_poc_spec.md for the full spec this implements.
"""

import os

from flask import Flask, jsonify, render_template, request, send_file, abort

from capture import start_capture

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


@app.route("/capture", methods=["POST"])
def capture():
    data = request.get_json(silent=True) or {}
    interface = (data.get("interface") or "wlan1mon").strip()
    simulate = bool(data.get("simulate", False))
    llc_snap_dispatch = bool(data.get("llc_snap_dispatch", False))

    raw_duration = data.get("duration", DEFAULT_DURATION)
    duration = int(raw_duration) if raw_duration not in (None, "") else None

    raw_max_packets = data.get("max_packets", DEFAULT_MAX_PACKETS)
    max_packets = int(raw_max_packets) if raw_max_packets not in (None, "") else None

    if not interface:
        return jsonify({"error": "Interface name is required."}), 400

    if duration is None and max_packets is None:
        return jsonify({"error": "Choose at least one stop condition: time, packet count, or both."}), 400

    session = start_capture(interface, simulate, duration, max_packets, CAPTURES_DIR,
                             llc_snap_dispatch=llc_snap_dispatch)
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


@app.route("/download/<capture_id>")
def download(capture_id):
    session = SESSIONS.get(capture_id)
    if session is None:
        abort(404, description="Unknown capture_id")
    if session.status != "done" or not session.csv_path:
        abort(409, description="Capture is not finished yet.")
    return send_file(session.csv_path, as_attachment=True)


if __name__ == "__main__":
    os.makedirs(CAPTURES_DIR, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
