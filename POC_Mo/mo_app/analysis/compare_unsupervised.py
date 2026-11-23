"""Compare unsupervised detectors on the sensor's stored per-second features.

Split (by time, no shuffling):
  train  2026-10-09 .. 10-24   (fit)
  valid  2026-11-02 .. 11-08   (calibrate threshold to <= 1 alarm event / hour)
  test   2026-11-09 .. 11-22   (false alarms on unseen normal traffic; injected attacks)
Seconds flagged by a rule (b_alert) are left out of every split as possibly abnormal.
Positives: synthetic attacks injected into random test seconds (feature level),
plus the 5 AWID3 attack seconds of each Model C test vector.

Usage:
  python compare_unsupervised_cache.py captures/monitor/features.csv <work dir>   # once: -> <work dir>/feat.npz
  python compare_unsupervised.py <work dir> <Model C test_vectors dir> [model name ...]
Results go to <work dir>/results_*.json. Report: analysis/reports/unsupervised_comparison.html
"""
import json, sys, time
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.decomposition import PCA
from sklearn.mixture import GaussianMixture
from sklearn.neural_network import MLPRegressor
from sklearn.metrics import roc_auc_score

S = sys.argv[1]
TV = sys.argv[2]
rng = np.random.default_rng(0)
z = np.load(S + "/feat.npz")
cols = list(z["cols"]); X = z["X"].astype("float64"); w = z["win"]; b = z["b"]
C = {c: i for i, c in enumerate(cols)}
ts = lambda d: int(np.datetime64(d + "T00:00:00") .astype("datetime64[s]").astype("int64")) - 7 * 3600
ok = ~b
tr = ok & (w >= ts("2026-10-09")) & (w < ts("2026-10-25"))
va = ok & (w >= ts("2026-11-02")) & (w < ts("2026-11-09"))
te = ok & (w >= ts("2026-11-09")) & (w < ts("2026-11-23"))
Xtr_all = X[tr]
Xtr = Xtr_all[rng.choice(len(Xtr_all), min(200_000, len(Xtr_all)), replace=False)]
Xva, wva = X[va], w[va]
Xte, wte = X[te], w[te]
print(f"train {tr.sum():,} s (fit sample {len(Xtr):,}) | valid {va.sum():,} s | test {te.sum():,} s", flush=True)

# ---------------------------------------------------------------- attacks
def inject(base, kind, k):
    A = base.copy()
    def add(c, v): A[:, C[c]] += v
    if kind == "deauth flood":
        add("deauth", k); add("mgmt", k); add("frames", k); add("deauth_to_one_client_10s", 10 * k)
    elif kind == "spoofed deauth":
        add("deauth", k); add("mgmt", k); add("frames", k); add("deauth_seq_out_of_order", k); add("deauth_to_one_client_10s", 10 * k)
    elif kind == "disassoc flood":
        add("disassoc", k); add("mgmt", k); add("frames", k); add("deauth_to_one_client_10s", 10 * k)
    elif kind == "auth flood":
        add("auth", k); add("mgmt", k); add("frames", k); add("n_sa", k)
    elif kind == "assoc flood":
        add("assoc_req", k); add("mgmt", k); add("frames", k); add("n_sa", k)
    elif kind == "beacon flood":
        add("beacon", k); add("mgmt", k); add("frames", k); add("n_ssid", k); add("n_bssid", k); add("n_sa", k)
    elif kind == "evil twin (new BSSID)":
        add("new_bssid_known_ssid", 1); add("max_bssid_per_ssid", 1); add("n_bssid", 1); add("beacon", 10); add("mgmt", 10); add("frames", 10)
    elif kind == "evil twin (cloned BSSID)":
        add("tsf_offset_switches", k); add("bssid_beacon_rate", k); add("beacon", k); add("mgmt", k); add("frames", k); add("bssid_signal_range", 20)
    elif kind == "RTS/CTS flood":
        add("rts", k); add("cts", k); add("ctrl", 2 * k); add("frames", 2 * k)
    elif kind == "probe flood":
        add("probe_req", k); add("mgmt", k); add("frames", k); add("n_sa", k)
    elif kind == "ARP spoofing":
        add("arp_ip_mac_flips_10s", 2); add("arp_ips_per_mac_60s", 2); add("arp", k); add("data", k); add("frames", k)
        A[:, C["arp_reply_ratio"]] = 1.0
    return A

KINDS = {"deauth flood": (3, 30), "spoofed deauth": (1, 10), "disassoc flood": (3, 30), "auth flood": (5, 50),
         "assoc flood": (5, 50), "beacon flood": (20, 200), "evil twin (new BSSID)": (1, 1),
         "evil twin (cloned BSSID)": (3, 10), "RTS/CTS flood": (50, 500), "probe flood": (20, 200), "ARP spoofing": (5, 30)}
N_INJ = 2000
base_idx = rng.choice(len(Xte), N_INJ, replace=False)
ATT = {}
for kind, (weak, strong) in KINDS.items():
    ATT[f"{kind} · weak"] = inject(Xte[base_idx], kind, weak)
    ATT[f"{kind} · strong"] = inject(Xte[base_idx], kind, strong)
aw = {}
for n in ("attack_deauth_awid3", "attack_evil_twin_awid3"):
    q = json.load(open(f"{TV}/request_{n}.json"))
    rows = np.array([[wd["features"][c] for c in cols] for wd in q["windows"]], dtype="float64")
    wins = np.array([wd["win"] for wd in q["windows"]])
    aw[n + " attack"] = rows[wins >= q["predict_from"]]
    aw[n + " pre-attack normal"] = rows[wins < q["predict_from"]]

# ---------------------------------------------------------------- models
GENERIC = ["signal_mean", "len_mean", "mgmt", "ctrl", "data", "protected_ratio", "n_dest_mac", "tcp"]
ATTACK_COLS = [i for c, i in C.items() if c not in GENERIC + ["signal_std", "frames"]]

class Prep:
    """log1p on non-negative columns, robust scale (median / IQR, from training)."""
    def __init__(self, Xf, idx=None, log=True):
        self.idx = idx if idx is not None else list(range(Xf.shape[1])); self.log = log
        T = self._t(Xf)
        self.med = np.median(T, 0); q = np.percentile(T, [25, 75], 0); iqr = q[1] - q[0]
        sd = T.std(0); self.sc = np.where(iqr > 0, iqr, np.where(sd > 0, sd, 1.0))
    def _t(self, A):
        A = A[:, self.idx]
        if self.log:
            A = np.where(A >= 0, np.log1p(np.clip(A, 0, None)), A)
        return A
    def __call__(self, A): return (self._t(A) - self.med) / self.sc

def ecod_fit(T):
    return np.sort(T, 0)
def ecod_score(srt, T):
    n = srt.shape[0]; s = np.zeros(len(T))
    for j in range(T.shape[1]):
        right = n - np.searchsorted(srt[:, j], T[:, j], side="left")     # one-sided: higher = rarer
        s += -np.log((right + 1) / (n + 1))
    return s

def hbos_fit(T, bins=50):
    H = []
    for j in range(T.shape[1]):
        h, e = np.histogram(T[:, j], bins=bins); H.append((e, (h + 1) / (h.sum() + bins)))
    return H
def hbos_score(H, T):
    s = np.zeros(len(T))
    for j, (e, p) in enumerate(H):
        k = np.clip(np.searchsorted(e, T[:, j], side="right") - 1, 0, len(p) - 1)
        out = T[:, j] > e[-1]                                            # beyond training range: rarest bin / 10
        s += -np.log(np.where(out, p.min() / 10, p[k]))
    return s

MODELS = {}
def model(name):
    def deco(fn): MODELS[name] = fn; return fn
    return deco

@model("A: IsolationForest 36 raw (current)")
def m_if_raw():
    m = IsolationForest(n_estimators=300, random_state=0).fit(Xtr)
    return lambda A: -m.score_samples(A)

@model("IsolationForest 36 log+scaled")
def m_if_log():
    p = Prep(Xtr); m = IsolationForest(n_estimators=300, random_state=0).fit(p(Xtr))
    return lambda A: -m.score_samples(p(A))

@model("IsolationForest attack features only (log)")
def m_if_att():
    p = Prep(Xtr, ATTACK_COLS); m = IsolationForest(n_estimators=300, random_state=0).fit(p(Xtr))
    return lambda A: -m.score_samples(p(A))

@model("ECOD one-sided (log)")
def m_ecod():
    p = Prep(Xtr); srt = ecod_fit(p(Xtr))
    return lambda A: ecod_score(srt, p(A))

@model("HBOS one-sided (log)")
def m_hbos():
    p = Prep(Xtr); H = hbos_fit(p(Xtr))
    return lambda A: hbos_score(H, p(A))

@model("Robust z max, one-sided (log)")
def m_z():
    p = Prep(Xtr)
    return lambda A: p(A).max(1)

@model("PCA reconstruction (log)")
def m_pca():
    p = Prep(Xtr); T = p(Xtr); m = PCA(n_components=0.95, random_state=0).fit(T)
    return lambda A: ((lambda U: ((U - m.inverse_transform(m.transform(U))) ** 2).sum(1))(p(A)))

@model("Gaussian mixture, 8 comp (log)")
def m_gmm():
    p = Prep(Xtr); m = GaussianMixture(8, covariance_type="full", random_state=0, reg_covar=1e-3).fit(p(Xtr)[:100_000])
    return lambda A: -m.score_samples(p(A))

@model("LOF novelty, k=35 (log)")
def m_lof():
    p = Prep(Xtr); m = LocalOutlierFactor(n_neighbors=35, novelty=True).fit(p(Xtr)[:40_000])
    return lambda A: -m.score_samples(p(A))

@model("Autoencoder MLP 36-16-6-16-36 (log)")
def m_ae():
    p = Prep(Xtr); T = p(Xtr)[:100_000]
    m = MLPRegressor(hidden_layer_sizes=(16, 6, 16), max_iter=60, early_stopping=True, random_state=0).fit(T, T)
    return lambda A: ((lambda U: ((U - m.predict(U)) ** 2).sum(1))(p(A)))

@model("IsolationForest 36 raw, 4096 samples/tree")
def m_if_big():
    m = IsolationForest(n_estimators=300, max_samples=4096, random_state=0).fit(Xtr)
    return lambda A: -m.score_samples(A)

@model("IsolationForest 36 log, 4096 samples/tree")
def m_if_big_log():
    p = Prep(Xtr); m = IsolationForest(n_estimators=300, max_samples=4096, random_state=0).fit(p(Xtr))
    return lambda A: -m.score_samples(p(A))

def _pct(ref):
    srt = np.sort(ref)
    return lambda s: np.searchsorted(srt, s, side="right") / len(srt)

@model("Ensemble: max percentile of GMM, robust z, ECOD")
def m_ens():
    parts = [m_gmm(), m_z(), m_ecod()]
    ref = Xtr[rng.choice(len(Xtr), 50_000, replace=False)]
    cdfs = [_pct(f(ref)) for f in parts]
    # beyond the training maximum: keep ordering by adding the raw excess (tiny)
    return lambda A: np.max([c(f(A)) + 1e-6 * np.tanh(f(A)) for f, c in zip(parts, cdfs)], axis=0)

# ---------------------------------------------------------------- evaluation
def events(wins):
    if not len(wins): return 0
    return int(1 + (np.diff(np.sort(wins)) > 3).sum())

def block_sample(Xs, ws, hours_every=4):
    """every 4th hour, whole hours (keeps runs of seconds together for event counting)."""
    keep = ((ws // 3600) % hours_every) == 0
    return Xs[keep], ws[keep]

only = sys.argv[3:] or list(MODELS)
Xva_s, wva_s = block_sample(Xva, wva)
Xte_s, wte_s = block_sample(Xte, wte)
print(f"valid sample {len(Xva_s):,} s, test sample {len(Xte_s):,} s", flush=True)
res = {}
for name in only:
    t0 = time.time(); score = MODELS[name](); fit_s = time.time() - t0
    t0 = time.time(); s_tr = score(Xtr[:50_000]); s_va = score(Xva_s); s_te = score(Xte_s); sc_s = (time.time() - t0) / (50_000 + len(Xva_s) + len(Xte_s)) * 1000
    thr_p = np.percentile(s_tr, 99.5)
    # calibrate on validation: lowest threshold giving <= 1 event/hour
    hours_va = len(Xva_s) / 3600
    cand = np.quantile(s_va, np.linspace(0.95, 0.99999, 400))
    thr_c = next((t for t in cand if events(wva_s[s_va > t]) / hours_va <= 1.0), cand[-1])
    hours_te = len(Xte_s) / 3600
    r = {"fit_s": round(fit_s, 1), "score_ms_per_1k": round(sc_s, 2),
         "test_fa_per_h_p995": round(events(wte_s[s_te > thr_p]) / hours_te, 2),
         "test_fa_per_h_calibrated": round(events(wte_s[s_te > thr_c]) / hours_te, 2),
         "det_p995": {}, "det_cal": {}, "auc": {}}
    neg = s_te
    for k, A in list(ATT.items()) + list(aw.items()):
        sa = score(A)
        r["det_p995"][k] = round(float((sa > thr_p).mean()), 3)
        r["det_cal"][k] = round(float((sa > thr_c).mean()), 3)
        if "pre-attack" not in k:
            r["auc"][k] = round(float(roc_auc_score(np.r_[np.zeros(len(neg)), np.ones(len(sa))], np.r_[neg, sa])), 3)
    syn = [v for k, v in r["det_cal"].items() if "·" in k]
    r["mean_det_cal_synthetic"] = round(float(np.mean(syn)), 3)
    r["mean_det_cal_weak"] = round(float(np.mean([v for k, v in r["det_cal"].items() if "weak" in k])), 3)
    r["mean_auc_synthetic"] = round(float(np.mean([v for k, v in r["auc"].items() if "·" in k])), 3)
    res[name] = r
    print(f"\n### {name}  fit {r['fit_s']}s  score {r['score_ms_per_1k']} ms/1k  FA/h p99.5={r['test_fa_per_h_p995']} cal={r['test_fa_per_h_calibrated']}"
          f"  det(cal) all={r['mean_det_cal_synthetic']} weak={r['mean_det_cal_weak']}  AUC={r['mean_auc_synthetic']}", flush=True)
    json.dump(res, open(f"{S}/results_{'_'.join(str(MODELS and list(MODELS).index(n)) for n in only)}.json", "w"), indent=1)
