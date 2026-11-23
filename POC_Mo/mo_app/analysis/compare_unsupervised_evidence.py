"""Extra evidence for the report: data timeline, feature sparsity under
Isolation Forest's 256-row subsamples, and operating curves (false alarms per
hour on unseen test data vs. share of injected attack seconds detected).
Usage: python compare_unsupervised_evidence.py <work dir with feat.npz> <Model C test_vectors dir>
"""
import json, os, sys
import numpy as np

S, TV = sys.argv[1], sys.argv[2]
HERE = os.path.dirname(os.path.abspath(__file__))
src = open(os.path.join(HERE, "compare_unsupervised.py")).read()
sys.argv = [os.path.join(HERE, "compare_unsupervised.py"), S, TV]
exec(src[: src.index("only = sys.argv[3:]")])

out = {"cols": cols, "sizes": {"train": int(tr.sum()), "fit_sample": len(Xtr), "valid": int(va.sum()), "test": int(te.sum())}}

# 1. timeline: seconds per local day, rule-flagged seconds, split
day = (w + 7 * 3600) // 86400
tl = []
for d in np.unique(day):
    m = day == d
    t0 = int(d * 86400 - 7 * 3600)
    split = "train" if ts("2026-10-09") <= t0 < ts("2026-10-25") else "valid" if ts("2026-11-02") <= t0 < ts("2026-11-09") \
        else "test" if ts("2026-11-09") <= t0 < ts("2026-11-23") else "unused"
    tl.append({"day": str(np.datetime64(int(d), "D")), "seconds": int(m.sum()), "rule_flagged": int((m & b).sum()), "split": split})
out["timeline"] = tl

# 2. sparsity: how often a random 256-row subsample has the feature constant
R = np.random.default_rng(1)
sp = []
for c in cols:
    v = Xtr_all[:, C[c]]
    nz = float((v != 0).mean())
    const = np.mean([np.ptp(v[R.choice(len(v), 256, replace=False)]) == 0 for _ in range(400)])
    sp.append({"feature": c, "nonzero_share": round(nz, 5), "constant_in_256_subsample": round(float(const), 3)})
out["sparsity"] = sp

# 3. operating curves
Xte_s, wte_s = block_sample(Xte, wte)
hours = len(Xte_s) / 3600
pos = np.vstack(list(ATT.values()))
lab = np.repeat(np.arange(len(ATT)), N_INJ)
curves = {}
for name in ["A: IsolationForest 36 raw (current)", "IsolationForest 36 raw, 4096 samples/tree", "Robust z max, one-sided (log)",
             "Autoencoder MLP 36-16-6-16-36 (log)", "Gaussian mixture, 8 comp (log)", "Ensemble: max percentile of GMM, robust z, ECOD"]:
    f = MODELS[name](); sn = f(Xte_s); sp_ = f(pos)
    pts = []
    for q in np.r_[np.linspace(0.97, 0.999, 30), 1 - np.logspace(-3, -6, 30)]:
        t = np.quantile(sn, q)
        fa = events(wte_s[sn > t]) / hours
        det = float(np.mean([(sp_[lab == i] > t).mean() for i in range(len(ATT))]))
        pts.append([round(fa, 3), round(det, 4)])
    curves[name] = pts
    print(name, "done", flush=True)
out["curves"] = curves
out["attacks"] = list(ATT)
json.dump(out, open(S + "/evidence.json", "w"), indent=1)
