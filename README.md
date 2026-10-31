# wids-edge

Software for the **capture device** of [WNDA System](https://github.com/wnda-system): a mini PC with a USB Wi-Fi adapter in monitor mode that passively listens to 802.11 traffic and detects anomalies on site.

> 🚧 **Status:** capture, per-second features and on-device detection run today as a standalone service. Integration with the central backend is in development.

## What it does today

| Capability | Where |
|---|---|
| Capture 802.11 frames in monitor mode and extract Radiotap, MAC-layer and selected upper-layer fields | `mo_app/capture.py` |
| One-click captures to CSV, with optional attack ground-truth labelling, through a local web UI | `mo_app/app.py`, `templates/index.html` |
| Continuous monitoring: raw frames saved in 5-minute gzip CSV chunks with a JSON sidecar (interface, channel, versions, git revision) | `mo_app/monitor.py` |
| 36 features per one-second window (no MAC or IP addresses) | `mo_app/analysis/features.py` |
| Live anomaly detection with rule-based and learned detectors, a growing baseline and periodic refits; alerts written to `alerts.jsonl` and shown at `/monitor` | `mo_app/monitor.py`, `analysis/detector.py`, `detection_rules.md` |
| Optional remote model ("Model C") queried in shadow mode over an SSH tunnel | `mo_app/model_c_client.py`, `ops/model-c-tunnel.service` |
| Runs as a systemd service, resumes monitoring after a restart | `mo_app/wifi-capture.service` |
| Freeze diagnostics and automatic reboot on kernel hang | `mo_app/ops/` |

## Planned integration with WNDA System

```
Wi-Fi traffic ──► sniffer ──► feature windows (every ~1 s) ──► wids-backend
                     │
                     └──► rolling raw captures ──► MinIO (via presigned URL)
```

| Item | Status |
|---|---|
| Send feature windows to `wids-backend`, buffering locally when offline | 🚧 Planned |
| Align the feature set with the model-training pipeline (`features_v3`) | 🚧 Planned |
| Upload raw capture chunks to object storage | 🚧 Planned |
| Send a heartbeat to the backend every minute (status, CPU, disk, clock offset) | 🚧 Planned |
| Pseudonymise MAC addresses with HMAC-SHA256 before anything leaves the device | 🚧 Planned |
| Replay recorded captures into the system as a virtual device | 🚧 Planned |

## Repository layout

```
mo_app/
  app.py, capture.py        web UI and frame capture / field extraction
  monitor.py                continuous capture, features, detection, alerts
  analysis/                 feature extraction, detectors, offline evaluation, Model C checks
  model_c_client.py         client for the remote model (shadow mode)
  ops/                      systemd units and system settings for the sensor (see ops/README.md)
  test_vectors/             small synthetic captures for tests
  templates/                web UI pages
  *.md                      design notes: detection rules, anomaly detection, Model C plans
wifi-sniffer/               earlier command-line sniffer (kept for reference)
```

## Requirements

- Ubuntu (tested on a Celeron N4000 mini PC, 8 GB RAM)
- USB Wi-Fi adapter that supports monitor mode
- Python 3.10+
- Root privileges for packet capture

## Quick start

Put the adapter into monitor mode:

```bash
iw dev                                   # find the adapter name
sudo ip link set <interface> down
sudo iw dev <interface> set type monitor
sudo ip link set <interface> up
```

Run the app once by hand:

```bash
cd mo_app
./run.sh
```

Or install it as a service (recommended on the sensor):

```bash
sudo install -m 644 mo_app/wifi-capture.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now wifi-capture
```

Edit the paths inside `wifi-capture.service` if the repository lives elsewhere. Do not run `./run.sh` while the service is running; both use port 5000.

See [`mo_app/README.md`](mo_app/README.md) and [`mo_app/ops/README.md`](mo_app/ops/README.md) for passwordless launch, simulation mode, the Model C tunnel and troubleshooting.

## Configuration outside the repository

Secrets and machine-specific values never go into git. They live on the sensor:

| File | Contents | Template |
|---|---|---|
| `/etc/wifi-capture/model_c.json` | Model C URL and on/off switch | `mo_app/ops/model_c.json.example` |
| `/etc/wifi-capture/model_c.token` | Model C bearer token (mode 600) | — |
| `/etc/wifi-capture/tunnel.env` | `TUNNEL_TARGET=<user>@<host>` for the SSH tunnel | `mo_app/ops/tunnel.env.example` |

## Operating notes

- **Lock the channel** to the access point under observation. Channel hopping breaks per-second feature windows.
- **Keep the clock in sync** with NTP. Alerts and field-test ground truth depend on accurate timestamps.
- The web UI runs as root and has no login. **Do not expose it on untrusted networks.**
- Raw captures contain real MAC addresses. Never commit them to this repository.
- The built-in Realtek `rtw88` Wi-Fi card has caused hard freezes on this hardware; see `mo_app/ops/README.md` for the mitigations in place.

## Contributing

- Branch from `dev`, open a pull request back to `dev`. `main` receives releases only.
- Pull request titles follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:` …).
- Feature branches are squash-merged into `dev`; `dev` is merged into `main` with a merge commit.

## Team

- Naran Wongvuttisaroj
- Boonyapon Boontub
