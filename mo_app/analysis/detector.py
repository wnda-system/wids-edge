"""Detectors A (IsolationForest) and B (per-feature rules), fitted on a table
of per-second baseline windows. Shared by anomaly_detect.py and the live
monitor. See ../anomaly_detection_notes.md.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

try:
    from .features import HINTS
except ImportError:  # run as a plain script from analysis/
    from features import HINTS

# deauth/disassoc/auth/assoc happen normally (clients leaving/joining), so
# "any occurrence" is too strict: flag a FLOOD instead, i.e. above both the
# training max (+20%) and an absolute per-second floor.
FLOOD_FLOOR = {"deauth": 10, "disassoc": 10, "auth": 10, "assoc_req": 10,
               # per-entity features: normal is ~0-4, so a low floor is safe
               "deauth_to_one_client_10s": 5, "tsf_offset_switches": 3,
               "arp_ip_mac_flips_10s": 2, "arp_ips_per_mac_60s": 3}
# A new BSSID for a protected SSID, or a deauth whose seq doesn't fit the AP's
# own counter, alerts on a single occurrence.
NEVER_SEEN = ["new_bssid_known_ssid", "deauth_seq_out_of_order"]


class Detector:
    def __init__(self, Xtr):
        self.feats = list(Xtr.columns)
        self.n_train = len(Xtr)
        self.model = IsolationForest(n_estimators=300, contamination="auto", random_state=0).fit(Xtr)
        self.thr = float(np.percentile(-self.model.score_samples(Xtr), 99.5))
        self.med = Xtr.median()
        self.iqr = (Xtr.quantile(0.75) - Xtr.quantile(0.25)).replace(0, np.nan).fillna(Xtr.std()).replace(0, 1)
        # One-sided: attacks add frames/APs/flags, so only an INCREASE alerts.
        self.z_limit = (((Xtr - self.med) / self.iqr).max() * 1.2).clip(lower=5)
        self.train_max = Xtr.max()
        self.never_seen = list(NEVER_SEEN)
        # No IP changed MAC at all in the baseline -> the first change is the
        # anomaly (otherwise fall back to the flood floor: real DHCP reuse).
        if self.train_max.get("arp_ip_mac_flips_10s", 0) == 0:
            self.never_seen.append("arp_ip_mac_flips_10s")

    def flood_limit(self, f):
        return float(max(self.train_max[f] * 1.2, FLOOD_FLOOR[f]))

    def scores(self, X):
        return -self.model.score_samples(X[self.feats])

    def b_hits(self, row):
        z = (row[self.feats] - self.med) / self.iqr
        hits = []
        for f in self.feats:
            if f in self.never_seen:
                if row[f] > 0:
                    hits.append(f)
            elif f in FLOOD_FLOOR:
                if row[f] > self.flood_limit(f):
                    hits.append(f)
            elif z[f] > self.z_limit[f]:
                hits.append(f)
        return hits

    def explain(self, row, top=3):
        z = (row[self.feats] - self.med) / self.iqr
        order = z.abs().sort_values(ascending=False).index[:top]
        return [f"{k}={row[k]:.2f}{'↑' if z[k] > 0 else '↓'} (normal≈{self.med[k]:.2f}, z={z[k]:+.1f})"
                + (f" → {HINTS[k]}" if k in HINTS and z[k] > 0 else "")
                for k in order if abs(z[k]) >= 3]

    def raw_limits(self):
        """Every alert threshold in feature units — compared between retrains
        to tell whether the baseline has stopped moving (Brain Power)."""
        lim = {}
        for f in self.feats:
            if f in self.never_seen:
                continue
            lim[f] = self.flood_limit(f) if f in FLOOD_FLOOR else float(self.med[f] + self.z_limit[f] * self.iqr[f])
        lim["_iforest_thr"] = self.thr
        return pd.Series(lim)
