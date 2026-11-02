# WiFi Packet Capture POC — Build Spec

Give this whole file to your AI coding agent (e.g. Claude Code) as the prompt.

## Objective
Build a proof-of-concept web application, accessible via `http://<host-ip>:<port>`
in any browser on the LAN, that:
1. Lets a user capture WiFi traffic from a monitor-mode USB adapter with one button click.
2. Extracts a defined set of raw packet fields from each captured frame.
3. Saves the results to a CSV file inside the application's own folder.
4. Has a simple, clear, non-technical-friendly UI.

## Environment
- OS: Linux
- Capture device: USB WiFi adapter with monitor-mode support, already switched into
  monitor mode (e.g. `wlan1mon` via `sudo airmon-ng start wlan1`)
- Python 3.10+
- Requires root privileges (or `CAP_NET_RAW` / `CAP_NET_ADMIN` capabilities) to open
  raw sockets for packet capture

## Stack
- Backend: Python + Flask, bound to `0.0.0.0:<port>` (not `127.0.0.1`, so other devices
  on the LAN can reach it)
- Packet capture: `scapy` (pure Python, easiest to pull fields out of) — use `pyshark`/
  `tshark` subprocess instead only if exact Wireshark field-name parity turns out to matter
- Frontend: single static HTML page + vanilla JS, calling the backend via `fetch()` —
  no framework needed for a POC
- Capture runs in a background thread; the button triggers start, capture auto-stops
  after a fixed duration/packet count, and the UI polls a status endpoint until done

## Functional Requirements

### 1. Web UI (single page)
- Header: app title, target interface name (text field or dropdown, default `wlan1mon`)
- One primary button: "Capture" → shows spinner/disabled while capturing → re-enables
  with "Done ✓" and packet count when finished
- Below the button: summary of the last capture (packet count, file path, timestamp)
- "Download CSV" link/button appears once the capture completes

### 2. Backend endpoints
- `GET /` — serves the UI
- `POST /capture` — starts a capture (duration- or packet-count-limited for the POC,
  e.g. 15s or 200 packets, whichever comes first); runs in a background thread and
  returns a `capture_id`
- `GET /status/<capture_id>` — returns `idle | capturing | done | error` plus packets
  captured so far
- `GET /download/<capture_id>` — serves the resulting CSV file

### 3. Capture logic
- Verify the interface is already in monitor mode before capturing — don't try to
  auto-configure it in the POC, just fail with a clear error if it isn't
- Sniff with scapy, e.g.:
  `scapy.all.sniff(iface="wlan1mon", prn=handler, timeout=15, store=False)`
- For each packet, extract the RAW field values listed under "Fields to extract" below
  (not the one-hot columns — see the schema note)
- Buffer rows in memory, flush to CSV once the capture ends

### 4. CSV output
- Location: `./captures/capture_<YYYYMMDD_HHMMSS>.csv` inside the app folder
  (create the folder if it doesn't exist)
- One row per packet, one column per extracted raw field; missing fields → `-1`
  (matches the missingness convention already used in the source ML project)
- Include `frame.time_epoch` and `frame.number` as extra columns for debugging/ordering
  even though they're excluded from the trained feature set — drop them before ever
  feeding this data to a model

## Schema note — read before extracting fields
`params.md` (attached separately) describes the model's **351 already one-hot-encoded
training columns** — e.g. `tcp.flags.ack_0`, `wlan.ssid_ASUS`, `http.request.method_GET`.
A live capture does not produce these directly. It naturally gives you the underlying
RAW field instead — `tcp.flags.ack` (0/1), `wlan.ssid` ("ASUS"), `http.request.method`
("GET").

**This POC captures and stores raw field values only.** Turning raw values into the
exact 351-column format used in training requires the same fitted encoder/vocabulary
used during training (a saved `.pkl`/`.joblib` object — not present in `params.md`, and
not needed for this step). That mapping is a later step, once that encoder is available.

So the pipeline is: **capture raw fields → CSV now** → (later) **raw CSV → 351-column
model input, using the training-time encoder.**

## Fields to attempt extracting (grouped — extract whatever scapy/tshark actually
exposes per packet type; not every packet has every field)
- **frame**: frame.time_epoch, frame.number, frame.len, frame.time_delta, frame.encap_type
- **wlan / radiotap**: wlan.fc.type, wlan.fc.subtype, wlan.fc.retry, wlan.fc.protected,
  wlan.duration, wlan.seq, wlan.ssid, wlan.da (dest MAC — capture but exclude from any
  future model input per the source project's rule against identifier columns),
  radiotap.channel.freq, radiotap.datarate, wlan_radio.signal_dbm
- **arp**: arp.opcode, arp.hw.type, arp.proto.type
- **eapol**: eapol.type, eapol.len, eapol.keydes.key_len
- **ip**: ip.version
- **tcp**: tcp.flags.ack, tcp.flags.syn, tcp.flags.fin, tcp.flags.reset, tcp.flags.push,
  tcp.analysis.retransmission
- **dns**: dns.flags.response, dns.count.queries, dns.count.answers
- **http**: http.request.method, http.response.code
- **dhcp, smb, smb2, ssh, tls, mdns, nbss, icmpv6**: extract if present, else `-1`

## Acceptance criteria (POC "done")
1. `python app.py` starts a server reachable at `http://<lan-ip>:<port>` from another
   device on the same network.
2. Clicking "Capture" in the browser starts a real capture on the monitor-mode interface
   and visibly shows progress/status.
3. Capture stops automatically after the fixed duration/count; UI shows "Done" + packet count.
4. A CSV file appears in `./captures/` with one row per captured packet and the raw
   fields above as columns.
5. Errors (interface not in monitor mode, permission denied, etc.) are shown clearly in
   the UI, not swallowed silently.

## Explicitly out of scope for this POC
- One-hot encoding to match the 351-column training schema (needs the training-time encoder)
- Live model inference
- Authentication / access control (POC assumes a trusted LAN only)
- Persisting capture history across app restarts (in-memory registry is fine)
