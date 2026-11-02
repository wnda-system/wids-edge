# WiFi Packet Capture POC

Built from `wifi_capture_poc_spec.md`.

## Run it

Easiest way — double-click the desktop icon (see "Desktop icon" below), or:

```bash
cd ~/mo_app
./run.sh
```

First run sets up a Python environment and installs dependencies
automatically, then asks for your sudo password (needed to capture packets).
It'll keep asking every run unless you set up passwordless launch — see
below.

Then open the URL it prints — works from this computer (`http://localhost:5000`)
or from any other device on your LAN or WiFi network, since the server listens
on all of this machine's network interfaces at once. `run.sh` prints every
address you can use.

## Desktop icon

One-time setup:

```bash
chmod +x ~/mo_app/run.sh ~/mo_app/wifi-capture.desktop
cp ~/mo_app/wifi-capture.desktop ~/Desktop/
cp ~/mo_app/wifi-capture.desktop ~/.local/share/applications/
```

Double-click it to launch. The first click may show a "trust this
application?" prompt — that's normal for a new local `.desktop` file; click
through it once.

## Passwordless launch

By default, every launch asks for your sudo password (packet capture needs
root). To stop that, install a scoped `sudoers` rule that allows *only* this
one exact command to run as root without a password — nothing else is
affected:

```bash
sudo visudo -cf ~/mo_app/wifi-capture-sudoers && \
sudo cp ~/mo_app/wifi-capture-sudoers /etc/sudoers.d/wifi-capture && \
sudo chmod 0440 /etc/sudoers.d/wifi-capture
```

`run.sh` automatically detects this and skips the prompt from then on. To
undo it: `sudo rm /etc/sudoers.d/wifi-capture`.

(An earlier version of this app tried granting the Python interpreter a
`CAP_NET_RAW`/`CAP_NET_ADMIN` file capability instead of using `sudo`. That
turned out to be unreliable in practice — it can report success via
`setcap`/`getcap` while the actual capture still fails — so this app uses
real `sudo` instead, which is what your hardware has been confirmed to work
with.)

## Before a real capture

Type the interface name into the UI (defaults to `wlx1cbfce71ebe7`, this
machine's USB adapter) and click "Enable monitor mode" next to it — the app
runs the down / set-type-monitor / up sequence for you and confirms it
actually took effect before letting you capture. Only needed once per
adapter per boot. If you don't know the interface name yet, run `iw dev` in
a terminal to list your adapters — the app also has a "(how do I find
this?)" link with the same pointer.

That button calls the same three commands you'd otherwise run by hand:

```bash
iw dev                                    # find your adapter's interface name
sudo ip link set <interface-name> down
sudo iw dev <interface-name> set type monitor
sudo ip link set <interface-name> up
```

— useful to know if the button's error message points you at something the
UI can't fix for you (e.g. NetworkManager fighting over the interface, see
below), or if you'd rather just do it directly.

`71-rename-wifi-capture.rules` in this folder can give the adapter a
short permanent name instead — unused by default. If you already applied it
and want to undo it:

```bash
sudo rm /etc/udev/rules.d/71-rename-wifi-capture.rules
sudo udevadm control --reload-rules
sudo udevadm trigger
# then unplug and replug the adapter — it'll come back as wlx1cbfce71ebe7
```

If you also created `/etc/NetworkManager/conf.d/99-unmanaged-wlx.conf`
referencing `capture0`, change it back to `wlx1cbfce71ebe7` and run
`sudo systemctl restart NetworkManager`.

**Wireless settings/Network panel disappeared?** That happens if you ran
`airmon-ng check kill` — it stops NetworkManager (which also powers the
system's WiFi settings UI). Restore it with:

```bash
sudo airmon-ng stop <interface-name>
sudo systemctl start NetworkManager
```

Better long-term fix, so both a built-in WiFi adapter and a USB capture
adapter can work at the same time without killing NetworkManager at all: tell
NetworkManager to permanently ignore the capture adapter. Create
`/etc/NetworkManager/conf.d/99-unmanaged-wlx.conf`:

```
[keyfile]
unmanaged-devices=interface-name:wlx1cbfce71ebe7
```

Then `sudo systemctl restart NetworkManager`. After that, skip
`airmon-ng check kill` entirely and use the `iw`/`ip` commands above instead.

## Try it without hardware first

Check "Simulate capture (no hardware needed — for testing)" in the UI. This
exercises the full flow with generated fake packets, so you can confirm the
app works before touching the real adapter.

## Setting stop conditions

Each capture stops when it hits a time limit, a packet-count limit,
whichever of the two comes first, or when you click "Stop capture now" —
your choice. Toggle either checkbox off to use just one condition (at least
one must stay on). Time can be set in seconds, minutes, hours, or days.

## Live anomaly monitor (`/monitor`)

A proof-of-concept dashboard that captures continuously, scores every second
of traffic for WiFi attacks, and keeps learning what "normal" looks like.
Open `http://<host>:5000/monitor`, then:

1. (Optional) **Seed the baseline** from earlier capture folders — only ones
   recorded on the same channel and width.
2. **Start monitoring** (defaults: channel 100, 40 MHz HT40+ — keep them the
   same as the baseline).
3. Leave it running. Detectors are refitted every 10 minutes; **Brain Power**
   shows how far along that is (coverage of the 168 hours of a week, threshold
   stability, false alarms on not-yet-seen data).

Rule-based alerts (deauth/disassoc floods, spoofed deauth, evil twin, ARP
spoofing, …) are trusted from the start; alerts from the learned model alone
are marked low-confidence until Brain Power reaches 50%. "Demo without the
adapter" replays a recorded capture through the same pipeline.

To keep it running unattended (survives closing the terminal/SSH and
reboots, and resumes monitoring by itself), install it as a service instead of
using `./run.sh` — see the comments at the top of `wifi-capture.service`.

Everything is stored under `captures/monitor/` (raw frames as 5-minute
`.csv.gz` chunks, ~44 MB/hour on channel 100). The capture page refuses to use
the interface while the monitor holds it. Design notes and test results:
`anomaly_detection_notes.md`.

## Files

- `app.py` — Flask server (`/`, `/capture`, `/status/<id>`, `/stop/<id>`, `/download/<id>`)
- `capture.py` — field extraction (scapy) + simulate-mode packet generator
- `monitor.py` — live anomaly monitor (continuous capture, detection, learning, Brain Power)
- `templates/monitor.html` — the monitor dashboard
- `analysis/` — shared feature/detector code, offline evaluator (`anomaly_detect.py`),
  long baseline collector (`collect_baseline.py`)
- `templates/index.html` — the UI
- `run.sh` — one-click launcher (setup + start, via sudo)
- `wifi-capture.desktop` — desktop/app-menu icon, runs `run.sh`
- `wifi-capture-sudoers` — optional rule for passwordless launches
- `71-rename-wifi-capture.rules` — optional udev rule for a short adapter name (currently unused)
- `captures/` — created automatically; each capture writes
  `capture_<timestamp>.csv` here

## Moving this to another Ubuntu machine

Yes, this works on other Ubuntu machines — copy the whole `mo_app` folder
over and run `./run.sh` there. A few things to know:

- The `venv/` folder (once created) is machine-specific — don't copy it
  between machines; let `run.sh` recreate it on the new one (automatic, a
  few seconds).
- The one-time sudo/capability step in `run.sh` needs to run again on each
  new machine (it's per-machine, not per-folder).
- `71-rename-wifi-capture.rules` is tied to this specific adapter's MAC
  address (`1c:bf:ce:71:eb:e7`), so it'll rename that same physical USB
  adapter to `capture0` no matter which machine it's plugged into. A
  different adapter needs its own rule (or just use its default name).
- The target machine needs a monitor-mode-capable WiFi adapter and the `iw`
  / `airmon-ng` tools (`sudo apt install aircrack-ng` if missing).

## What's tested vs. what needs your hardware

Tested (simulate mode, in an isolated sandbox with no USB access): server
binds to all network interfaces, capture start/poll/done flow, time-only /
packet-only / both stop conditions, early stop via the Stop button, CSV
written with all 42 columns and correct row count, download endpoint, 404 on
unknown capture id, and the "interface not in monitor mode" error path.

Verified by you on your machine: real scapy capture against your actual
monitor-mode adapter, dual LAN+WiFi reachability, and the passwordless
launch flow end-to-end.

## Notes on field extraction

- Raw fields follow the spec exactly. Missing fields → `-1`.
- Most fields on encrypted WiFi traffic will be `-1` — WPA2/3 encrypts the
  payload, so scapy can't see the IP/TCP/DNS/HTTP layers inside it, only the
  outer 802.11/radiotap headers (signal strength, SSID from beacons, retry
  flags, etc.). To get real IP/TCP/DNS values, point the capture at an open
  (unencrypted) network.
- `tcp.analysis.retransmission` — always `-1`. That's a Wireshark heuristic
  scapy doesn't compute; if you need it, swap the sniff loop for a `tshark`
  subprocess (spec mentions this as a fallback option).
- `dhcp/smb/smb2/ssh/tls/mdns/nbss` — the spec didn't give exact raw field
  names for these, so they're written as presence flags (`1`/`-1`) based on
  well-known port numbers, e.g. `ssh.present` = 1 if TCP port 22 is involved.
- `icmpv6.present` similarly flags IPv6 + ICMPv6 packets.
