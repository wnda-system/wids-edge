# POC_Mo — proof of concept (Mo)

The sensor software built and run on the mini PC during the proof-of-concept
phase (Aug–Oct 2026), before the WNDA System architecture. It is what runs on
the sensor today; the production edge agent (feature uploader, pcap batches,
heartbeat) will be built next to it in this repository.

| Folder | What it is |
|---|---|
| [`mo_app/`](mo_app/) | Capture web UI (Default and Field-test profiles), live monitor with detectors A (Isolation Forest) and B (rules), Brain Power, training-data settings, Model C shadow client, systemd/ops files |
| [`wifi-sniffer/`](wifi-sniffer/) | Earlier command-line sniffer, kept for reference |

Start with [`mo_app/README.md`](mo_app/README.md); design notes are in
`mo_app/detection_rules.md`, `mo_app/anomaly_detection_notes.md` and
`mo_app/model_c_training_plan.md`.

## Raw data formats produced here

| Item | Where it is defined |
|---|---|
| Raw CSV columns (164 fields per frame) | `FIELD_ORDER` in `mo_app/capture.py` |
| Raw schema versions (2 = default, 3 = field profile: `wlan.da` by DS bits) | `RAW_SCHEMA_VERSION` / `FIELD_RAW_SCHEMA_VERSION` in `mo_app/capture.py` |
| `.json` sidecar next to every CSV | `write_sidecar()` callers in `capture.py` and `monitor.py` |
| `<capture>_ground_truth.csv` (`start_epoch, end_epoch, attack, notes`) | `CaptureSession.mark()` in `capture.py` |
| 36 per-second features (`FEATURE_VERSION` 2) | `windows()` in `mo_app/analysis/features.py` |
| `wlan.da` / `msgnr` test frames and expected values | `mo_app/test_vectors/` |

## Moving the running sensor to this layout

The sensor's checkout used to have `mo_app/` at the repository root. Its
`venv/` and `captures/` (several GB of data) are not tracked, so a `git pull`
leaves them behind in the old folder. On the sensor, after pulling:

```bash
sudo systemctl stop wifi-capture
mv mo_app/venv mo_app/captures POC_Mo/mo_app/
sudo install -m 644 POC_Mo/mo_app/wifi-capture.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl start wifi-capture
```

`wifi-capture.service` here already points at `POC_Mo/mo_app`. The sudoers
file and desktop launcher still use the old `~/mo_app` path from the very first
setup; adjust them if you use them.
