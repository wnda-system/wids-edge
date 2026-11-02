"""
Client for Model C — the AWID3-trained attack classifier served over HTTP from
the training machine (contract: model_c_training_plan.md, section 6).

Runs in SHADOW mode: every second's prediction is logged to
captures/monitor/model_c_shadow.jsonl and shown on the dashboard, but it
raises no alerts and has no effect on training A/B. Only the 36 per-second
window features are sent — no MAC/IP/SSID.

Configuration (re-read automatically when the files change, no restart needed):
    /etc/wifi-capture/model_c.json    {"enabled": true, "url": "http://<hpc-host>:8500"}
    /etc/wifi-capture/model_c.token   the Bearer token alone (chmod 600)
See ops/model_c.json.example.

Network calls run on their own thread with a 2 s timeout and drop work when
busy, so a slow or dead service can never stall capture or detectors A/B.
"""
import json
import os
import queue
import threading
import time
import urllib.error
import urllib.request

from analysis.features import FEATURE_VERSION

CONFIG_PATH = "/etc/wifi-capture/model_c.json"
TOKEN_PATH = "/etc/wifi-capture/model_c.token"
TIMEOUT = 2.0
INFO_REFRESH = 600          # re-read /v1/info every 10 min (model may be redeployed)
SENSOR_ID = "momoparadise-ch100"


class ModelCClient:
    def __init__(self, log_path, log=print, config_path=CONFIG_PATH, token_path=TOKEN_PATH):
        self.log_path, self._log = log_path, log
        self.config_path, self.token_path = config_path, token_path
        self._cfg_mtime = None
        self.url = self.token = None
        self.enabled = False
        self.info = None
        self._info_at = 0
        self.calls_ok = self.calls_failed = self.dropped = 0
        self.last_ok = self.last_error_at = None
        self.last_error = None
        self.latency_ms = None
        self.recent = []                 # (win, predicted) of shadow alerts, last 24 h
        self._q = queue.Queue(maxsize=1)
        threading.Thread(target=self._worker, daemon=True).start()

    # ------------------------------------------------------------- config
    def _reload_config(self):
        try:
            mtimes = tuple(os.path.getmtime(p) if os.path.exists(p) else None
                           for p in (self.config_path, self.token_path))
        except OSError:
            mtimes = (None, None)
        if mtimes == self._cfg_mtime:
            return
        self._cfg_mtime = mtimes
        self.enabled, self.url, self.token, self.info = False, None, None, None
        try:
            with open(self.config_path) as f:
                cfg = json.load(f)
            with open(self.token_path) as f:
                token = f.read().strip()
        except FileNotFoundError:
            return                          # not configured yet: stay off quietly
        except (OSError, ValueError) as e:
            self._fail(f"config: {e}")
            return
        if cfg.get("enabled") and cfg.get("url") and token:
            self.enabled, self.url, self.token = True, cfg["url"].rstrip("/"), token
            self._log(f"Model C client enabled → {self.url} (shadow mode)")

    # ------------------------------------------------------------- HTTP
    def _request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read())

    def _fail(self, msg):
        self.calls_failed += 1
        self.last_error, self.last_error_at = msg, time.time()

    def _ensure_info(self):
        if self.info is not None and time.time() - self._info_at < INFO_REFRESH:
            return True
        info = self._request("GET", "/v1/info")
        if info.get("feature_version") != FEATURE_VERSION:
            self._fail(f"feature_version mismatch: service {info.get('feature_version')}, sensor {FEATURE_VERSION}")
            self.info = None
            return False
        if self.info is None or info.get("model") != self.info.get("model"):
            self._log(f"Model C service: model {info.get('model')}, context {info.get('context_seconds')} s")
        self.info, self._info_at = info, time.time()
        return True

    # ------------------------------------------------------------- per tick
    def submit(self, win_df, new_wins):
        """Called by the monitor after each detection pass. win_df = this
        pass's windows() output (≈ last 90 s); new_wins = seconds just judged."""
        self._reload_config()
        if not self.enabled or not len(new_wins):
            return
        try:
            self._q.put_nowait((win_df.drop(columns=["file"], errors="ignore"),
                                int(min(new_wins)), int(max(new_wins))))
        except queue.Full:
            self.dropped += 1               # previous call still running: skip, never block

    def _worker(self):
        while True:
            win_df, predict_from, predict_to = self._q.get()
            try:
                self._call(win_df, predict_from, predict_to)
            except urllib.error.HTTPError as e:
                self._fail(f"HTTP {e.code} {e.reason}")
                if e.code == 409:
                    self.info = None        # feature_version changed on one side
            except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
                self._fail(f"{type(e).__name__}: {getattr(e, 'reason', e)}")

    def _call(self, win_df, predict_from, predict_to):
        if not self._ensure_info():
            return
        ctx = int(self.info.get("context_seconds", 0))
        # only seconds the monitor has finished judging: the newest ones in
        # win_df are still filling up and would be predicted again next pass
        rows = win_df[(win_df.index >= predict_from - ctx) & (win_df.index <= predict_to)]
        body = {
            "sensor_id": SENSOR_ID,
            "feature_version": FEATURE_VERSION,
            "windows": [{"win": int(w), "features": {k: float(v) for k, v in r.items()}}
                        for w, r in rows.iterrows()],
            "predict_from": predict_from,
        }
        t = time.time()
        resp = self._request("POST", "/v1/predict", body)
        self.latency_ms = round((time.time() - t) * 1000)
        self.calls_ok += 1
        self.last_ok = time.time()
        now = time.time()
        with open(self.log_path, "a") as f:
            for r in resp.get("results", []):
                f.write(json.dumps({"win": r["win"], "model": resp.get("model"), "predicted": r.get("predicted"),
                                    "alert": bool(r.get("alert")),
                                    "proba": {k: round(v, 4) for k, v in r.get("proba", {}).items()}}) + "\n")
                if r.get("alert"):
                    self.recent.append((r["win"], r.get("predicted")))
        self.recent = [x for x in self.recent if x[0] >= now - 86400]

    # ------------------------------------------------------------- status
    def status(self):
        self._reload_config()
        by_class = {}
        for _, c in self.recent:
            by_class[c] = by_class.get(c, 0) + 1
        healthy = (self.enabled and self.last_ok is not None and time.time() - self.last_ok < 30
                   and (self.last_error_at is None or self.last_ok > self.last_error_at))
        return {
            "configured": self.enabled, "mode": "shadow", "url": self.url, "healthy": healthy,
            "model": (self.info or {}).get("model"), "context_seconds": (self.info or {}).get("context_seconds"),
            "thresholds": (self.info or {}).get("thresholds"),
            "calls_ok": self.calls_ok, "calls_failed": self.calls_failed, "dropped": self.dropped,
            "latency_ms": self.latency_ms, "last_ok": self.last_ok,
            "last_error": self.last_error, "last_error_at": self.last_error_at,
            "shadow_alerts_24h": by_class,
        }
