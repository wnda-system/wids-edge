"""Load features.csv once into <work dir>/feat.npz for compare_unsupervised.py.
Usage: python compare_unsupervised_cache.py captures/monitor/features.csv <work dir>
"""
import sys
import numpy as np
import pandas as pd

src, out = sys.argv[1], sys.argv[2]
f = pd.read_csv(src, low_memory=False)
f = f[pd.to_numeric(f.win, errors="coerce").notna()]
cols = [c for c in f.columns if c not in ("win", "file", "a_score", "a_alert", "b_alert")]
X = f[cols].apply(pd.to_numeric, errors="coerce").fillna(0).to_numpy("float32")
win = f.win.astype("float64").astype("int64").to_numpy()
flag = lambda s: s.astype(str).isin(["True", "1", "1.0"]).to_numpy()
a, b = flag(f.a_alert), flag(f.b_alert)
o = np.argsort(win, kind="stable"); win, X, a, b = win[o], X[o], a[o], b[o]
u = np.r_[True, np.diff(win) > 0]                     # one row per second
np.savez(out + "/feat.npz", win=win[u], X=X[u], a=a[u], b=b[u], cols=np.array(cols))
print(len(cols), "features,", int(u.sum()), "seconds")
