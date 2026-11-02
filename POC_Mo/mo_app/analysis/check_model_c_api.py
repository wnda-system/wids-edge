"""Check the Model C service from this sensor before trusting it.

1. GET /v1/health and /v1/info (feature_version must match this sensor)
2. replay every test_vectors/request_*.json and compare with response_*.json
   (same predicted class / alert, probabilities within 1e-6)

    sudo venv/bin/python3 analysis/check_model_c_api.py ~/model_c_inbox/model_c/test_vectors

Uses the URL/token from /etc/wifi-capture/model_c.{json,token} (hence sudo),
or pass --url and --token-file. Standard library only.
"""
import argparse, glob, json, os, sys, time, urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analysis.features import FEATURE_VERSION

ap = argparse.ArgumentParser()
ap.add_argument("vectors_dir")
ap.add_argument("--url")
ap.add_argument("--token-file", default="/etc/wifi-capture/model_c.token")
args = ap.parse_args()
url = (args.url or json.load(open("/etc/wifi-capture/model_c.json"))["url"]).rstrip("/")
token = open(args.token_file).read().strip()


def call(method, path, body=None):
    req = urllib.request.Request(url + path, data=json.dumps(body).encode() if body else None, method=method,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    t = time.time()
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read()), (time.time() - t) * 1000


ok = True
health, ms = call("GET", "/v1/health")
print(f"health: {health} ({ms:.0f} ms)")
info, _ = call("GET", "/v1/info")
print(f"info: model={info.get('model')} feature_version={info.get('feature_version')} "
      f"context={info.get('context_seconds')}s classes={info.get('classes')}")
if info.get("feature_version") != FEATURE_VERSION:
    print(f"FAIL: service feature_version {info.get('feature_version')} != sensor {FEATURE_VERSION}")
    ok = False

reqs = sorted(glob.glob(os.path.join(args.vectors_dir, "request_*.json")))
if not reqs:
    sys.exit(f"no request_*.json in {args.vectors_dir}")
for rq in reqs:
    expected = json.load(open(rq.replace("request_", "response_")))
    got, ms = call("POST", "/v1/predict", json.load(open(rq)))
    bad = []
    exp_by_win = {r["win"]: r for r in expected["results"]}
    if len(got["results"]) != len(exp_by_win):
        bad.append(f"{len(got['results'])} results, expected {len(exp_by_win)}")
    for r in got["results"]:
        e = exp_by_win.get(r["win"])
        if e is None:
            bad.append(f"unexpected win {r['win']}")
            continue
        if (r["predicted"], r["alert"]) != (e["predicted"], e["alert"]):
            bad.append(f"win {r['win']}: {r['predicted']}/{r['alert']} vs {e['predicted']}/{e['alert']}")
        diff = max(abs(r["proba"].get(k, 0) - v) for k, v in e["proba"].items())
        if diff > 1e-6:
            bad.append(f"win {r['win']}: proba differs by {diff:.2e}")
    print(f"{os.path.basename(rq)}: {len(got['results'])} results, {ms:.0f} ms — " + ("OK" if not bad else "FAIL"))
    for b in bad[:5]:
        print("   ", b)
    ok &= not bad
print("ALL OK" if ok else "SOME CHECKS FAILED")
sys.exit(0 if ok else 1)
