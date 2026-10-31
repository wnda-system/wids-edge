#!/bin/bash
# Package what the training machine needs for Model C (see model_c_training_plan.md):
# the exact capture/feature code, docs, and this site's normal traffic.
#
#   analysis/make_training_bundle.sh [raw_days] [output]
#     raw_days  how many days of the newest raw chunks to include (default 1, ~400 MB/day)
#     output    default ~/model_c_bundle.tar.gz
#
# The bundle contains real MAC/IP addresses from this network — keep it inside the team.
set -euo pipefail
APP="$(cd "$(dirname "$0")/.." && pwd)"
DAYS="${1:-1}"
OUT="${2:-$HOME/model_c_bundle.tar.gz}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
B="$STAGE/model_c_bundle"
mkdir -p "$B/code/analysis" "$B/docs" "$B/ours/raw"

cp "$APP/capture.py" "$B/code/"
cp "$APP"/analysis/{__init__,features,detector,anomaly_detect}.py "$B/code/analysis/"
cp "$APP"/{model_c_training_plan,detection_rules,anomaly_detection_notes}.md "$B/docs/"
cp "$APP/model_c_training_plan.md" "$B/README.md"

MON="$APP/captures/monitor"
# features.csv may carry NUL padding from an old power loss — strip it
tr -d '\000' < "$MON/features.csv" > "$B/ours/features.csv"
cp "$MON/context.json" "$B/ours/"
# newest N days of complete raw chunks (skip the one being written right now)
N=$(( DAYS * 288 ))
mapfile -t CHUNKS < <(ls -1t "$MON"/raw/*.csv.gz)
for f in "${CHUNKS[@]:1:$N}"; do
    if gzip -t "$f" 2>/dev/null; then cp "$f" "$B/ours/raw/"; fi
done

"$APP/venv/bin/python3" - > "$B/env.txt" <<'EOF'
import sys, numpy, pandas, sklearn, scapy, joblib
from analysis.features import FEATURE_VERSION
print(f"python {sys.version.split()[0]}\nnumpy {numpy.__version__}\npandas {pandas.__version__}")
print(f"scikit-learn {sklearn.__version__}\nscapy {scapy.__version__}\njoblib {joblib.__version__}")
print(f"FEATURE_VERSION {FEATURE_VERSION}")
EOF
echo "channel 100 HT40+ (5500 MHz, 40 MHz), adapter RTL8822BU (rtw88)" >> "$B/env.txt"

tar -C "$STAGE" -czf "$OUT" model_c_bundle
echo "wrote $OUT ($(du -h "$OUT" | cut -f1)); raw chunks: $(ls "$B/ours/raw" | wc -l), feature seconds: $(( $(wc -l < "$B/ours/features.csv") - 1 ))"
