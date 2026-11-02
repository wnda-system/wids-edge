# System settings for the sensor machine

Changes made outside the app on this machine, kept here so they can be
reviewed or undone. Added 2026-10-09 after repeated hard freezes.

| File | Installed as | Purpose |
|---|---|---|
| `../wifi-capture.service` | `/etc/systemd/system/wifi-capture.service` | Run the app as a service (see top of that file) |
| — | `/etc/modprobe.d/rtw88.conf` | `options rtw88_core disable_lps_deep=y` and `options rtw88_pci disable_aspm=y`: turn off WiFi power-saving modes linked to rtw88 freezes |
| `90-autoreboot-on-hang.conf` | `/etc/sysctl.d/90-autoreboot-on-hang.conf` | Panic on soft/hard lockup or a 120 s hung task, then reboot after 10 s |
| `model-c-tunnel.service` | `/etc/systemd/system/model-c-tunnel.service` | SSH tunnel sensor `127.0.0.1:8500` → br1 `127.0.0.1:8500` (Model C service), runs as `molecule`, restarts itself |
| — | `~molecule/.ssh/model_c_tunnel` + a line in br1's `~<hpc-user>/.ssh/authorized_keys` | Dedicated tunnel key, restricted on br1 to `restrict,port-forwarding,permitopen="127.0.0.1:8500",command="/bin/false"` (no shell) |
| `model_c.json.example` | `/etc/wifi-capture/model_c.json` + `/etc/wifi-capture/model_c.token` | URL and Bearer token of the Model C service on the training machine (see below) |
| `freeze-watch.sh` + `.service` | `/usr/local/sbin/freeze-watch.sh`, `/etc/systemd/system/freeze-watch.service` | At every boot, append to `/var/log/freeze-watch.log` how the previous boot ended: `clean` / `FROZE` / `PANIC` |

Install (sysctl + freeze-watch):

```bash
sudo install -m 644 ops/90-autoreboot-on-hang.conf /etc/sysctl.d/ && sudo sysctl --system >/dev/null \
  && sudo install -m 755 ops/freeze-watch.sh /usr/local/sbin/ \
  && sudo install -m 644 ops/freeze-watch.service /etc/systemd/system/ \
  && sudo systemctl daemon-reload && sudo systemctl enable freeze-watch.service
```

Read the freeze log: `cat /var/log/freeze-watch.log`

Model C client (shadow mode — `model_c_client.py`). Picked up within seconds, no restart needed:

```bash
sudo install -m 600 /dev/stdin /etc/wifi-capture/model_c.json <<< '{"enabled": true, "url": "http://127.0.0.1:8500"}'
sudo install -m 600 <token file copied from the training machine> /etc/wifi-capture/model_c.token
sudo venv/bin/python3 analysis/check_model_c_api.py <test_vectors dir>     # must end with ALL OK
```

Turn it off: set `"enabled": false` (or delete the two files).

Undo everything:

```bash
sudo rm /etc/sysctl.d/90-autoreboot-on-hang.conf /etc/modprobe.d/rtw88.conf
sudo systemctl disable freeze-watch.service && sudo rm /etc/systemd/system/freeze-watch.service /usr/local/sbin/freeze-watch.sh
sudo reboot
```

Limits: auto-reboot only works for hangs the kernel can still detect. A
lock-up at the hardware level (e.g. a wedged PCIe link) can stop the
watchdogs too; `freeze-watch` will still record it as `FROZE` after the
next manual power cycle.
