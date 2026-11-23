"""Detectors A (anomaly ensemble) and B (per-feature rules), fitted on a
table of per-second baseline windows. Shared by anomaly_detect.py and the live
monitor. See ../anomaly_detection_notes.md, and analysis/reports/ for why A is
an ensemble (GMM + robust z + ECOD) and no longer an Isolation Forest.
"""
import numpy as np
import pandas as pd
from sklearn.mixture import GaussianMixture

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


FIT_ROWS = 200_000       # rows the ensemble is fitted on (random sample of the training table)
GMM_ROWS = 100_000       # rows for the Gaussian mixture (the slow part: ~1 min on the sensor)
REF_ROWS = 300_000       # rows that turn each part's score into a percentile
FA_TARGET = 1.0          # alarm events / hour the threshold is calibrated to
EVENT_GAP = 3            # seconds closer than this are one event (as in the monitor)


class _Prep:
    """log1p on non-negative columns, then robust scaling (median / IQR)."""

    def __init__(self, X):
        T = self._log(X)
        self.med = np.median(T, 0)
        q25, q75 = np.percentile(T, [25, 75], 0)
        iqr, sd = q75 - q25, T.std(0)
        self.scale = np.where(iqr > 0, iqr, np.where(sd > 0, sd, 1.0))

    @staticmethod
    def _log(X):
        return np.where(X >= 0, np.log1p(np.clip(X, 0, None)), X)

    def __call__(self, X):
        return (self._log(X) - self.med) / self.scale


class Ensemble:
    """Detector A. Three one-class scores on log + robust-scaled features, each
    turned into "how rare is this among the training seconds" (percentile),
    combined with max, reported as rarity = -log10(1 - percentile):
      - Gaussian mixture (8 full-covariance components): unusual combinations
      - robust z, largest over features, one-sided: one feature far too high
      - ECOD, one-sided: product of per-feature upper-tail probabilities
    Chosen over Isolation Forest on 2026-11-23: on held-out traffic with
    injected attacks it caught 46 % of attack seconds at <= 1 false alarm/h,
    where the forest caught ~0 %: attack features are zero in almost every
    second (deauth in 99.7 %), so many of its 256-row trees can't split on them
    at all (deauth: 43 %, disassoc/assoc_req: 90 %), and each split picks one
    of 36 features at random, so a flood is rarely isolated faster than an
    ordinary busy second)."""

    def __init__(self, X, seed=0):
        rng = np.random.default_rng(seed)
        X = np.asarray(X)               # keep float32: the full table is large, only samples go to float64
        fit = X[rng.choice(len(X), min(FIT_ROWS, len(X)), replace=False)].astype("float64")
        self.prep = _Prep(fit)
        T = self.prep(fit)
        self.gmm = GaussianMixture(min(8, max(1, len(T) // 1000)), covariance_type="full",
                                   reg_covar=1e-3, random_state=seed).fit(T[:GMM_ROWS])
        self.ecod_ref = np.sort(T, 0)
        ref = X[rng.choice(len(X), min(REF_ROWS, len(X)), replace=False)].astype("float64")
        self.ref = [np.sort(p) for p in self._parts(ref)]

    def _parts(self, X):
        T = self.prep(np.asarray(X, dtype="float64"))
        n = len(self.ecod_ref)
        ecod = np.zeros(len(T))
        for j in range(T.shape[1]):
            right = n - np.searchsorted(self.ecod_ref[:, j], T[:, j], side="left")
            ecod += -np.log((right + 1) / (n + 1))
        return [-self.gmm.score_samples(T), T.max(1), ecod]

    def score(self, X):
        pct = []
        for s, ref in zip(self._parts(X), self.ref):
            # ties broken beyond the reference's top by the part's own score
            pct.append(np.searchsorted(ref, s, side="right") / len(ref) + 1e-6 * np.tanh(s))
        return -np.log10(np.clip(1 - np.max(pct, 0), 1e-7, None))


def _events(wins):
    w = np.sort(np.asarray(wins))
    return 0 if not len(w) else int(1 + (np.diff(w) > EVENT_GAP).sum())


def calibrate(scores, wins, target=FA_TARGET):
    """Lowest threshold that raises at most `target` alarm events per hour
    on `scores` (seconds the model was not fitted on)."""
    hours = len(scores) / 3600
    for t in np.quantile(scores, np.linspace(0.95, 0.99999, 400)):
        if _events(wins[scores > t]) / hours <= target:
            return float(t)
    return float(np.max(scores))


class Detector:
    def __init__(self, Xtr, Xcal=None):
        """Xtr: training seconds (B's limits and A's fit). Xcal: later seconds,
        index = unix second, used only to set A's threshold to <= 1 alarm/h.
        Without them (too little data yet) the threshold falls back to the
        99.9th percentile of the training scores."""
        self.feats = list(Xtr.columns)
        self.n_train = len(Xtr)
        self.model = Ensemble(Xtr[self.feats])
        if Xcal is not None and len(Xcal) >= 6 * 3600:
            self.thr = calibrate(self.model.score(Xcal[self.feats]), np.asarray(Xcal.index))
            self.thr_source = f"calibrated to <= {FA_TARGET:g} alarm/h on {len(Xcal) / 3600:.0f} h not used for fitting"
        else:
            self.thr = float(np.percentile(self.model.score(Xtr[self.feats]), 99.9))
            self.thr_source = "99.9th percentile of the training scores (too little data to calibrate)"
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
        return self.model.score(X[self.feats])

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
        lim["_a_thr"] = self.thr
        return pd.Series(lim)
