"""Build analysis/reports/unsupervised_comparison.html (self-contained: inline
SVG charts, no external files) from unsupervised_results.json and
unsupervised_evidence.json produced by compare_unsupervised*.py.
Usage: python make_unsupervised_report.py
"""
import html
import json
import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))
R = json.load(open(os.path.join(HERE, "reports", "unsupervised_results.json")))
E = json.load(open(os.path.join(HERE, "reports", "unsupervised_evidence.json")))
OUT = os.path.join(HERE, "reports", "unsupervised_comparison.html")
esc = html.escape

CUR = "A: IsolationForest 36 raw (current)"
ENS = "Ensemble: max percentile of GMM, robust z, ECOD"
SHORT = {
    CUR: "IF 256 (เดิม)", "IsolationForest 36 log+scaled": "IF log", "IsolationForest attack features only (log)": "IF ฟีเจอร์โจมตี",
    "ECOD one-sided (log)": "ECOD", "HBOS one-sided (log)": "HBOS", "Robust z max, one-sided (log)": "Robust z",
    "PCA reconstruction (log)": "PCA", "Gaussian mixture, 8 comp (log)": "GMM", "LOF novelty, k=35 (log)": "LOF",
    "Autoencoder MLP 36-16-6-16-36 (log)": "Autoencoder", "IsolationForest 36 raw, 4096 samples/tree": "IF 4096",
    "IsolationForest 36 log, 4096 samples/tree": "IF 4096 log", ENS: "Ensemble (เลือก)",
}
DESC = {
    CUR: "Isolation Forest 300 ต้น ต้นละ 256 แถว บนค่าดิบ 36 ฟีเจอร์ — ตัวที่ใช้อยู่เดิม",
    "IsolationForest 36 log+scaled": "Isolation Forest เดิม แต่แปลง log1p + robust scale ก่อน",
    "IsolationForest attack features only (log)": "Isolation Forest เฉพาะฟีเจอร์ที่เกี่ยวกับการโจมตี (ตัด 10 ฟีเจอร์ทั่วไป)",
    "IsolationForest 36 raw, 4096 samples/tree": "Isolation Forest ต้นละ 4,096 แถว (ให้เห็นค่าหายากมากขึ้น)",
    "IsolationForest 36 log, 4096 samples/tree": "Isolation Forest ต้นละ 4,096 แถว บนค่า log + scale",
    "ECOD one-sided (log)": "Empirical-CDF outlier: รวม −log ความน่าจะเป็นหางขวาของแต่ละฟีเจอร์",
    "HBOS one-sided (log)": "Histogram-based outlier score 50 ช่องต่อฟีเจอร์",
    "Robust z max, one-sided (log)": "ค่า z (median/IQR) สูงสุดข้ามฟีเจอร์ ดูเฉพาะขาขึ้น",
    "PCA reconstruction (log)": "ความคลาดเคลื่อนการสร้างกลับจาก PCA ที่เก็บ 95% variance",
    "Gaussian mixture, 8 comp (log)": "Gaussian mixture 8 กลุ่ม full covariance — −log likelihood",
    "LOF novelty, k=35 (log)": "Local Outlier Factor (k=35) fit บน 40,000 แถว",
    "Autoencoder MLP 36-16-6-16-36 (log)": "Autoencoder (MLP 16-6-16) — ความคลาดเคลื่อนการสร้างกลับ",
    ENS: "รวม GMM + Robust z + ECOD: แปลงแต่ละคะแนนเป็น percentile ของข้อมูลเทรน แล้วใช้ค่าสูงสุด",
}
ATTACK_DEF = [
    ("deauth flood", "deauth, mgmt, frames +k; deauth_to_one_client_10s +10k", "3", "30"),
    ("spoofed deauth", "เหมือน deauth flood + deauth_seq_out_of_order +k", "1", "10"),
    ("disassoc flood", "disassoc, mgmt, frames +k; deauth_to_one_client_10s +10k", "3", "30"),
    ("auth flood", "auth, mgmt, frames, n_sa +k (MAC สุ่ม)", "5", "50"),
    ("assoc flood", "assoc_req, mgmt, frames, n_sa +k", "5", "50"),
    ("beacon flood", "beacon, mgmt, frames, n_ssid, n_bssid, n_sa +k", "20", "200"),
    ("evil twin (new BSSID)", "new_bssid_known_ssid, max_bssid_per_ssid, n_bssid +1; beacon +10", "1", "1"),
    ("evil twin (cloned BSSID)", "tsf_offset_switches, bssid_beacon_rate, beacon +k; bssid_signal_range +20", "3", "10"),
    ("RTS/CTS flood", "rts, cts +k; ctrl, frames +2k", "50", "500"),
    ("probe flood", "probe_req, mgmt, frames, n_sa +k", "20", "200"),
    ("ARP spoofing", "arp_ip_mac_flips_10s +2, arp_ips_per_mac_60s +2, arp/data/frames +k, arp_reply_ratio = 1", "5", "30"),
]

order = sorted(R, key=lambda n: -R[n]["mean_det_cal_synthetic"])
syn_keys = [k for k in R[CUR]["det_cal"] if "·" in k]
aw_keys = [k for k in R[CUR]["det_cal"] if "awid3" in k]

# ------------------------------------------------------------------ charts
FONT = 'font-family="inherit" font-size="12" fill="currentColor"'


def bars(rows, vmax, width=720, label_w=150, h=22, unit="", colors=None, fmt="{:.0%}"):
    """rows: [(label, value | [values], highlight)]"""
    series = max(len(v) if isinstance(v, list) else 1 for _, v, _ in rows)
    bh = (h - 6) / series
    H = len(rows) * h + 30
    plot = width - label_w - 60
    s = [f'<svg viewBox="0 0 {width} {H}" class="chart" role="img">']
    for i in range(6):
        x = label_w + plot * i / 5
        s.append(f'<line x1="{x:.1f}" y1="4" x2="{x:.1f}" y2="{H - 24}" class="grid"/>'
                 f'<text x="{x:.1f}" y="{H - 8}" text-anchor="middle" {FONT} class="muted">{fmt.format(vmax * i / 5)}{unit}</text>')
    for r, (lab, v, hi) in enumerate(rows):
        y = 6 + r * h
        s.append(f'<text x="{label_w - 8}" y="{y + h / 2}" text-anchor="end" dominant-baseline="middle" {FONT}'
                 f'{" font-weight=\"600\"" if hi else ""}>{esc(lab)}</text>')
        vals = v if isinstance(v, list) else [v]
        for j, val in enumerate(vals):
            wv = plot * min(val, vmax) / vmax
            c = (colors or ["var(--c1)", "var(--c2)"])[j]
            s.append(f'<rect x="{label_w}" y="{y + j * bh:.1f}" width="{max(wv, 1):.1f}" height="{bh - 2:.1f}" rx="2" fill="{c}"'
                     f'{" stroke=\"var(--ink)\" stroke-width=\"1\"" if hi else ""}/>'
                     f'<text x="{label_w + wv + 4:.1f}" y="{y + j * bh + bh / 2:.1f}" dominant-baseline="middle" {FONT}>{fmt.format(val)}{unit}</text>')
    s.append("</svg>")
    return "".join(s)


def heatmap(models, keys, vals, width=980):
    cw, lw, th = 66, 210, 96
    H = th + len(keys) * 22 + 10
    s = [f'<svg viewBox="0 0 {lw + cw * len(models) + 10} {H}" class="chart wide" role="img">']
    for j, m in enumerate(models):
        x = lw + j * cw + cw / 2
        s.append(f'<text transform="translate({x},{th - 6}) rotate(-45)" {FONT}{" font-weight=\"600\"" if m == ENS else ""}>{esc(SHORT[m])}</text>')
    for i, k in enumerate(keys):
        y = th + i * 22
        s.append(f'<text x="{lw - 8}" y="{y + 11}" text-anchor="end" dominant-baseline="middle" {FONT}>{esc(k)}</text>')
        for j, m in enumerate(models):
            v = vals[m][k]
            s.append(f'<rect x="{lw + j * cw + 1}" y="{y + 1}" width="{cw - 2}" height="20" rx="2" fill="var(--c1)" fill-opacity="{0.06 + 0.94 * v:.2f}"/>'
                     f'<text x="{lw + j * cw + cw / 2}" y="{y + 11}" text-anchor="middle" dominant-baseline="middle" {FONT} '
                     f'class="{"on" if v > 0.55 else ""}">{v:.0%}</text>')
    s.append("</svg>")
    return "".join(s)


def curves(cv, width=720, H=380):
    lx, rx, ty, by = 60, width - 170, 14, H - 44
    xs = lambda fa: lx + (rx - lx) * (math.log10(max(fa, 0.01)) + 2) / 4          # 0.01 .. 100 /h
    ys = lambda d: by - (by - ty) * d / 0.6
    s = [f'<svg viewBox="0 0 {width} {H}" class="chart" role="img">']
    for t in (0.01, 0.1, 1, 10, 100):
        s.append(f'<line x1="{xs(t):.1f}" y1="{ty}" x2="{xs(t):.1f}" y2="{by}" class="grid"/>'
                 f'<text x="{xs(t):.1f}" y="{by + 16}" text-anchor="middle" {FONT} class="muted">{t:g}</text>')
    for d in (0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6):
        s.append(f'<line x1="{lx}" y1="{ys(d):.1f}" x2="{rx}" y2="{ys(d):.1f}" class="grid"/>'
                 f'<text x="{lx - 6}" y="{ys(d):.1f}" text-anchor="end" dominant-baseline="middle" {FONT} class="muted">{d:.0%}</text>')
    s.append(f'<line x1="{xs(1):.1f}" y1="{ty}" x2="{xs(1):.1f}" y2="{by}" stroke="var(--warn)" stroke-dasharray="4 3"/>'
             f'<text x="{xs(1) + 4:.1f}" y="{ty + 10}" {FONT} fill="var(--warn)">เป้า ≤ 1 ครั้ง/ชม.</text>')
    s.append(f'<text x="{(lx + rx) / 2}" y="{H - 6}" text-anchor="middle" {FONT} class="muted">แจ้งผิดต่อชั่วโมงบนข้อมูลทดสอบ (log scale)</text>')
    pal = ["var(--c3)", "var(--c4)", "var(--c5)", "var(--c6)", "var(--c2)", "var(--c1)"]
    for i, (name, pts) in enumerate(cv.items()):
        pts = sorted((p for p in pts if p[0] > 0), key=lambda p: p[0])
        d = " ".join(f"{'M' if j == 0 else 'L'}{xs(fa):.1f},{ys(min(det, 0.6)):.1f}" for j, (fa, det) in enumerate(pts))
        wdt = 3 if name == ENS else 1.8
        s.append(f'<path d="{d}" fill="none" stroke="{pal[i]}" stroke-width="{wdt}"/>')
        s.append(f'<rect x="{rx + 14}" y="{ty + i * 22}" width="14" height="4" fill="{pal[i]}"/>'
                 f'<text x="{rx + 34}" y="{ty + i * 22 + 4}" dominant-baseline="middle" {FONT}>{esc(SHORT[name])}</text>')
    s.append("</svg>")
    return "".join(s)


def timeline(tl, width=980, H=170):
    lx, by, ty = 40, H - 40, 10
    n = len(tl)
    bw = (width - lx - 10) / n
    col = {"train": "var(--c1)", "valid": "var(--c2)", "test": "var(--c5)", "unused": "var(--muted-fill)"}
    s = [f'<svg viewBox="0 0 {width} {H}" class="chart wide" role="img">']
    for hr in (0, 12, 24):
        y = by - (by - ty) * hr / 24
        s.append(f'<line x1="{lx}" y1="{y:.1f}" x2="{width - 10}" y2="{y:.1f}" class="grid"/>'
                 f'<text x="{lx - 6}" y="{y:.1f}" text-anchor="end" dominant-baseline="middle" {FONT} class="muted">{hr}h</text>')
    for i, t in enumerate(tl):
        h = t["seconds"] / 3600
        y = by - (by - ty) * h / 24
        s.append(f'<rect x="{lx + i * bw + 1:.1f}" y="{y:.1f}" width="{bw - 2:.1f}" height="{by - y:.1f}" fill="{col[t["split"]]}">'
                 f'<title>{t["day"]}: {h:.1f} h ({t["split"]})</title></rect>')
        if i % 3 == 0:
            s.append(f'<text x="{lx + i * bw + bw / 2:.1f}" y="{by + 14}" text-anchor="middle" {FONT} class="muted">{t["day"][5:]}</text>')
    lg = [("train (fit)", "train"), ("valid (ตั้ง threshold)", "valid"), ("test (วัดผล)", "test"), ("ไม่ใช้", "unused")]
    for i, (lab, k) in enumerate(lg):
        x = lx + i * 190
        s.append(f'<rect x="{x}" y="{H - 14}" width="12" height="10" fill="{col[k]}"/><text x="{x + 18}" y="{H - 5}" {FONT}>{lab}</text>')
    s.append("</svg>")
    return "".join(s)


# ------------------------------------------------------------------ tables
def pct(v):
    return f"{v:.0%}"


main_rows = "".join(
    f'<tr class="{"pick" if n == ENS else "cur" if n == CUR else ""}"><td>{esc(SHORT[n])}</td><td>{esc(DESC[n])}</td>'
    f'<td class="n">{pct(R[n]["mean_det_cal_synthetic"])}</td><td class="n">{pct(R[n]["mean_det_cal_weak"])}</td>'
    f'<td class="n">{R[n]["mean_auc_synthetic"]:.3f}</td><td class="n">{R[n]["test_fa_per_h_calibrated"]:.2f}</td>'
    f'<td class="n">{R[n]["test_fa_per_h_p995"]:.1f}</td><td class="n">{R[n]["fit_s"]:.0f} วิ</td></tr>'
    for n in order)
att_rows = "".join(f"<tr><td>{esc(a)}</td><td>{esc(d)}</td><td class='n'>{w}</td><td class='n'>{s_}</td></tr>" for a, d, w, s_ in ATTACK_DEF)
sp = sorted((x for x in E["sparsity"] if x["feature"] in (
    "deauth", "disassoc", "auth", "assoc_req", "deauth_seq_out_of_order", "deauth_to_one_client_10s", "new_bssid_known_ssid",
    "tsf_offset_switches", "arp_ip_mac_flips_10s", "arp_ips_per_mac_60s", "rts", "beacon", "frames")), key=lambda x: -x["constant_in_256_subsample"])
sp_rows = "".join(f"<tr><td>{esc(x['feature'])}</td><td class='n'>{x['nonzero_share']:.2%}</td><td class='n'>{x['constant_in_256_subsample']:.0%}</td></tr>" for x in sp)
aw_rows = "".join(
    f"<tr><td>{esc(SHORT[n])}</td>" + "".join(f"<td class='n'>{R[n]['det_cal'][k]:.0%}</td>" for k in aw_keys) + "</tr>"
    for n in (CUR, "Gaussian mixture, 8 comp (log)", "Robust z max, one-sided (log)", ENS))
sz = E["sizes"]

heat_models = [ENS, "Gaussian mixture, 8 comp (log)", "Autoencoder MLP 36-16-6-16-36 (log)", "Robust z max, one-sided (log)",
               "ECOD one-sided (log)", "LOF novelty, k=35 (log)", "HBOS one-sided (log)", "PCA reconstruction (log)",
               "IsolationForest 36 raw, 4096 samples/tree", CUR]
det_vals = {m: R[m]["det_cal"] for m in heat_models}

ens, cur, gmm = R[ENS], R[CUR], R["Gaussian mixture, 8 comp (log)"]

page = f"""<!doctype html>
<html lang="th"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Unsupervised Detector Comparison</title>
<style>
:root{{--bg:#f8fafc;--card:#fff;--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--c1:#2563eb;--c2:#93c5fd;--c3:#94a3b8;--c4:#a855f7;--c5:#f59e0b;--c6:#14b8a6;--warn:#dc2626;--muted-fill:#cbd5e1;--pick:#eff6ff;--cur:#fef2f2}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{--bg:#0b1120;--card:#111827;--ink:#e5e7eb;--muted:#94a3b8;--line:#1f2937;--c1:#60a5fa;--c2:#1e40af;--c3:#64748b;--c4:#c084fc;--c5:#fbbf24;--c6:#2dd4bf;--warn:#f87171;--muted-fill:#334155;--pick:#172554;--cur:#3b0d0d}}}}
:root[data-theme="dark"]{{--bg:#0b1120;--card:#111827;--ink:#e5e7eb;--muted:#94a3b8;--line:#1f2937;--c1:#60a5fa;--c2:#1e40af;--c3:#64748b;--c4:#c084fc;--c5:#fbbf24;--c6:#2dd4bf;--warn:#f87171;--muted-fill:#334155;--pick:#172554;--cur:#3b0d0d}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.65 -apple-system,"Segoe UI","Noto Sans Thai",Sarabun,sans-serif}}
main{{max-width:1040px;margin:0 auto;padding:32px 16px 64px}} h1{{font-size:26px;margin:0 0 4px}} h2{{font-size:19px;margin:36px 0 10px;padding-top:8px;border-top:1px solid var(--line)}} h3{{font-size:16px;margin:20px 0 6px}}
.sub{{color:var(--muted);margin:0 0 20px}} .card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:12px 0}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}} .kpi{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}}
.kpi b{{display:block;font-size:24px}} .kpi span{{color:var(--muted);font-size:13px}}
table{{width:100%;border-collapse:collapse;font-size:13.5px}} th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}} th{{color:var(--muted);font-weight:600}}
td.n{{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}} tr.pick td{{background:var(--pick);font-weight:600}} tr.cur td{{background:var(--cur)}}
.scroll{{overflow-x:auto}} svg.chart{{width:100%;max-width:760px;height:auto;display:block;color:var(--ink)}} svg.wide{{max-width:100%}}
svg .grid{{stroke:var(--line)}} svg .muted{{fill:var(--muted)}} svg text.on{{fill:#fff}}
code{{font-size:12.5px;background:var(--line);padding:1px 5px;border-radius:4px}} .muted{{color:var(--muted)}} .note{{font-size:13px;color:var(--muted)}}
.legend{{display:flex;gap:16px;font-size:13px;color:var(--muted);margin-top:4px}} .legend i{{display:inline-block;width:12px;height:10px;margin-right:5px;border-radius:2px}}
</style></head><body><main>
<h1>เปรียบเทียบตัวตรวจจับแบบ Unsupervised (ตัวตรวจ A)</h1>
<p class="sub">WiFi anomaly monitor บน sensor ช่อง 100 · ทดสอบ 23 พ.ย. 2026 · ข้อมูลจริง 9 ต.ค. – 22 พ.ย. 2026 (≈ 2.65 ล้านวินาที) · 13 โมเดล</p>

<div class="card"><b>สรุป:</b> ตัวตรวจ A เดิม (Isolation Forest) ไม่สามารถจับการโจมตีที่จำลองใส่ลงในข้อมูลจริงได้ (0% ที่ threshold ที่แจ้งผิด ≤ 1 ครั้ง/ชม.)
ตัวที่ดีที่สุดโดยรวมคือ <b>Ensemble (GMM + Robust z + ECOD)</b> — จับได้เฉลี่ย {pct(ens['mean_det_cal_synthetic'])} ของวินาทีที่มีการโจมตี
แจ้งผิดบนข้อมูลใหม่ {ens['test_fa_per_h_calibrated']:.2f} ครั้ง/ชม. และ AUC สูงสุด ({ens['mean_auc_synthetic']:.3f}) จึงนำมาใช้แทนตัวตรวจ A ในระบบ</div>

<div class="kpis">
<div class="kpi"><span>Ensemble · จับได้เฉลี่ย</span><b>{pct(ens['mean_det_cal_synthetic'])}</b></div>
<div class="kpi"><span>Isolation Forest เดิม · จับได้เฉลี่ย</span><b>{pct(cur['mean_det_cal_synthetic'])}</b></div>
<div class="kpi"><span>Ensemble · แจ้งผิดบนข้อมูลใหม่</span><b>{ens['test_fa_per_h_calibrated']:.2f}/ชม.</b></div>
<div class="kpi"><span>Ensemble · AUC เฉลี่ย</span><b>{ens['mean_auc_synthetic']:.3f}</b></div>
</div>

<h2>1. ข้อมูลที่ใช้</h2>
<p>ฟีเจอร์ต่อวินาที 36 ตัว (<code>FEATURE_VERSION</code> 2) ที่ sensor คำนวณและบันทึกไว้ใน <code>captures/monitor/features.csv</code>
ไม่มี MAC/IP · ช่อง 100 HT40+ · มหาวิทยาลัย (KUWIN, eduroam, AIS) · ไม่มีการโจมตีจริงที่ทราบในช่วงนี้</p>
<div class="card">{timeline(E['timeline'])}
<p class="note">ชั่วโมงที่มีข้อมูลต่อวัน แบ่งตามเวลาโดยไม่สุ่มสลับ (กันข้อมูลรั่วระหว่างชุด) · ช่องว่าง 25 ต.ค. – 1 พ.ย. และ 12–16 พ.ย. คือช่วงที่ monitor ไม่ได้ทำงาน
· 23 พ.ย. ไม่ใช้เพราะสภาพแวดล้อมเปลี่ยน (สัญญาณเฉลี่ยกระโดดจาก −64 เป็น −43 dBm)</p></div>
<table><tr><th>ชุด</th><th>ช่วง</th><th>ใช้ทำอะไร</th><th class="n">วินาที</th></tr>
<tr><td>train</td><td>9–24 ต.ค.</td><td>fit โมเดล (สุ่ม {sz['fit_sample']:,} แถวสำหรับ fit)</td><td class="n">{sz['train']:,}</td></tr>
<tr><td>valid</td><td>2–8 พ.ย.</td><td>ตั้ง threshold: ค่าต่ำสุดที่แจ้งผิด ≤ 1 เหตุการณ์/ชม.</td><td class="n">{sz['valid']:,}</td></tr>
<tr><td>test</td><td>9–22 พ.ย.</td><td>วัดผล: แจ้งผิดบนข้อมูลที่ไม่เคยเห็น + การจับการโจมตีจำลอง</td><td class="n">{sz['test']:,}</td></tr></table>
<p class="note">ทุกชุดตัดวินาทีที่กฎ B แจ้งเตือนออก (อาจเป็นเหตุการณ์ผิดปกติจริง ไม่ควรนับเป็น "ปกติ")
· การนับแจ้งผิดใช้ทุกชั่วโมงที่ 4 แบบเต็มชั่วโมง (valid 142,163 / test 208,078 วินาที) เพื่อคงลำดับเวลาไว้สำหรับรวมเป็นเหตุการณ์</p>

<h2>2. วิธีทดสอบ</h2>
<h3>2.1 การโจมตีจำลอง (feature-level injection)</h3>
<p>ข้อมูลจริงไม่มีการโจมตีที่ทราบเวลา จึงสุ่มวินาทีปกติจริงจากชุด test 2,000 วินาที แล้ว<b>บวกผลของการโจมตีเพิ่มลงในฟีเจอร์</b>
แบบเดียวกับที่การโจมตีนั้นจะทำให้ตัวนับเพิ่มขึ้น (traffic ปกติยังอยู่ครบ) แต่ละแบบมีระดับเบา (k น้อย) และแรง (k มาก) รวม 22 ชุด</p>
<div class="scroll"><table><tr><th>การโจมตี</th><th>ฟีเจอร์ที่เพิ่ม</th><th class="n">k เบา</th><th class="n">k แรง</th></tr>{att_rows}</table></div>
<h3>2.2 ตัววัด</h3>
<ul>
<li><b>จับได้ (detection rate):</b> สัดส่วนของวินาทีที่มีการโจมตีจำลองที่คะแนนเกิน threshold</li>
<li><b>แจ้งผิด/ชม.:</b> จำนวนเหตุการณ์ที่แจ้งบนข้อมูลปกติ (วินาทีห่างกัน ≤ 3 วินาทีนับเป็นเหตุการณ์เดียว เหมือนในระบบจริง) หารด้วยชั่วโมง</li>
<li><b>Threshold แบบ calibrated:</b> ตั้งบนชุด valid ให้แจ้งผิด ≤ 1 ครั้ง/ชม. แล้วนำไปวัดบนชุด test — ทุกโมเดลถูกเทียบที่ระดับแจ้งผิดเท่ากัน จึงยุติธรรม</li>
<li><b>Threshold แบบเดิม (p99.5):</b> percentile 99.5 ของคะแนนบนข้อมูลเทรน (วิธีที่ระบบใช้อยู่เดิม)</li>
<li><b>AUC:</b> ความสามารถแยกวินาทีโจมตีออกจากวินาทีปกติของ test โดยไม่ขึ้นกับ threshold</li>
</ul>
<h3>2.3 ความเท่าเทียมของการทดสอบ</h3>
<p>ทุกโมเดลใช้ข้อมูลชุดเดียวกัน การแบ่งชุดเดียวกัน การสุ่มเดียวกัน (seed 0) และการโจมตีจำลองชุดเดียวกัน
· โมเดลที่ระบุ "(log)" ใช้ log1p + robust scale (median/IQR จากชุด train) แบบเดียวกัน
· "one-sided" = นับเฉพาะค่าที่สูงกว่าปกติ เพราะการโจมตีทำให้ตัวนับเพิ่มขึ้น</p>

<h2>3. ผลลัพธ์</h2>
<div class="scroll"><table>
<tr><th>โมเดล</th><th>รายละเอียด</th><th class="n">จับได้เฉลี่ย</th><th class="n">จับแบบเบา</th><th class="n">AUC</th><th class="n">แจ้งผิด/ชม. (calibrated)</th><th class="n">แจ้งผิด/ชม. (p99.5 เดิม)</th><th class="n">เวลา fit*</th></tr>
{main_rows}</table></div>
<p class="note">เรียงตามจับได้เฉลี่ย · แถวสีฟ้า = ตัวที่เลือก · แถวสีแดง = ตัวที่ใช้อยู่เดิม · *บน sensor (Celeron N4000) ขณะ monitor หยุด</p>

<h3>3.1 จับได้เฉลี่ยที่แจ้งผิด ≤ 1 ครั้ง/ชม.</h3>
<div class="card">{bars([(SHORT[n], [R[n]['mean_det_cal_synthetic'], R[n]['mean_det_cal_weak']], n == ENS) for n in order], 0.6)}
<div class="legend"><span><i style="background:var(--c1)"></i>ทุกการโจมตี</span><span><i style="background:var(--c2)"></i>เฉพาะแบบเบา</span></div></div>

<h3>3.2 แจ้งผิด vs. จับได้ (ทุก threshold)</h3>
<div class="card">{curves(E['curves'])}
<p class="note">แต่ละเส้นคือโมเดลหนึ่งตัวเมื่อเลื่อน threshold · ยิ่งเส้นสูงที่ฝั่งซ้ายยิ่งดี (จับได้มากโดยแจ้งผิดน้อย) · Isolation Forest ทั้งสองแบบแทบเป็นเส้นติดพื้นทุกระดับแจ้งผิด
· Ensemble อยู่สูงสุดในช่วงที่แจ้งผิดใกล้ 1 ครั้ง/ชม. ซึ่งเป็นช่วงที่ใช้งานจริง
· กราฟนี้เลื่อน threshold บนชุด test โดยตรงเพื่อดูรูปร่างของการแลกกัน ตัวเลขจึงต่างจากตารางที่ตั้ง threshold บนชุด valid เล็กน้อย (ตารางคือค่าที่ใช้ตัดสิน)</p></div>

<h3>3.3 จับได้แยกตามการโจมตี (threshold calibrated)</h3>
<div class="card scroll">{heatmap(heat_models, syn_keys, det_vals)}</div>
<p>สิ่งที่เห็นจากตาราง:</p>
<ul>
<li><b>Ensemble และ GMM จับ deauth/disassoc/assoc flood และ beacon/probe flood แบบแรงได้เกือบ 100%</b> Ensemble จับ RTS/CTS flood แบบแรงได้ {pct(ens['det_cal']['RTS/CTS flood · strong'])} (GMM {pct(gmm['det_cal']['RTS/CTS flood · strong'])})</li>
<li><b>ไม่มีโมเดลไหนจับ evil twin (BSSID ใหม่) ได้</b> เพราะช่วง train (15–24 ต.ค.) มี AP ใหม่รอ approve จำนวนมาก ฟีเจอร์ <code>new_bssid_known_ssid</code> จึงสูงเป็นปกติในข้อมูลเทรน</li>
<li><b>ARP spoofing จับได้น้อยทุกโมเดล</b> (≤ {pct(max(R[m]['det_cal']['ARP spoofing · strong'] for m in heat_models))})</li>
<li>สองกรณีนี้กฎ B จับได้ตั้งแต่ครั้งแรกอยู่แล้ว (<code>new_bssid_known_ssid</code>, <code>arp_ip_mac_flips_10s</code>) ระบบจึงต้องใช้ A และ B ร่วมกัน</li>
</ul>

<h2>4. ทำไม Isolation Forest เดิมจับไม่ได้</h2>
<p>Isolation Forest สร้างต้นไม้จากข้อมูลสุ่มต้นละ 256 แถว และแต่ละจุดแบ่งสุ่มเลือก 1 จาก 36 ฟีเจอร์ ฟีเจอร์ที่บอกการโจมตีเป็น 0 ในเกือบทุกวินาที
ใน 256 แถวที่สุ่มมาจึงมักเป็น 0 ทั้งหมด (ฟีเจอร์ค่าเดียว → ต้นไม้แบ่งด้วยฟีเจอร์นั้นไม่ได้) และแม้จะแบ่งได้ ก็มีโอกาสถูกเลือกแค่ 1/36 ต่อจุด
วินาทีที่มี deauth flood จึงไม่ได้ถูกแยกออกเร็วกว่าวินาทีปกติที่แค่ traffic เยอะ (คะแนนส่วนใหญ่มาจาก <code>len_mean</code>, <code>signal_mean</code>, ปริมาณเฟรม)</p>
<div class="scroll"><table><tr><th>ฟีเจอร์</th><th class="n">วินาทีที่ไม่เป็น 0 (train)</th><th class="n">ต้นไม้ที่ฟีเจอร์นี้มีค่าเดียวทั้ง 256 แถว</th></tr>{sp_rows}</table></div>
<p class="note">ทดสอบด้วยการสุ่ม 256 แถวจากชุด train 400 ครั้งต่อฟีเจอร์ · การเพิ่มเป็น 4,096 แถวต่อต้นทำให้ AUC ดีขึ้น ({R[CUR]['mean_auc_synthetic']:.3f} → {R['IsolationForest 36 raw, 4096 samples/tree']['mean_auc_synthetic']:.3f})
แต่ที่ระดับแจ้งผิด 1 ครั้ง/ชม. ยังจับได้แค่ {pct(R['IsolationForest 36 raw, 4096 samples/tree']['mean_det_cal_synthetic'])}</p>
<p>โมเดลที่ทำงานดี (GMM, Robust z, ECOD) <b>ดูทุกฟีเจอร์พร้อมกันทุกครั้ง</b> และใช้ log scale ทำให้การเพิ่มจาก 0 เป็น 3 ใน deauth มีน้ำหนักชัดเจน</p>

<h2>5. วิธีตั้ง threshold แบบเดิมใช้กับข้อมูลใหม่ไม่ได้</h2>
<p>ถ้าตั้ง threshold ที่ percentile 99.5 ของคะแนนบนข้อมูลเทรนแบบเดิม ทุกโมเดลแจ้งผิดบนข้อมูลใหม่ 3–31 ครั้ง/ชม. (คอลัมน์ "p99.5 เดิม" ในตารางผล)
เพราะคะแนนบนข้อมูลที่โมเดลเคยเห็นต่ำกว่าข้อมูลใหม่เสมอ และ traffic เปลี่ยนไปตามเวลา · <b>ข้อสรุป:</b> ต้องตั้ง threshold จากข้อมูลช่วงล่าสุดที่ไม่ได้ใช้ fit</p>
<div class="card">{bars([(SHORT[n], R[n]['test_fa_per_h_p995'], n == ENS) for n in order], 35, unit="/ชม.", fmt="{:.1f}")}</div>

<h2>6. ตรวจกับข้อมูล AWID3 (ใช้ไม่ได้)</h2>
<p>ลองใช้วินาทีการโจมตีจริงจาก AWID3 ที่แปลงเป็นฟีเจอร์ชุดเดียวกัน (5 วินาทีต่อชุด จาก test vectors ของ Model C) พร้อมวินาทีปกติก่อนการโจมตีของ AWID3 เอง:</p>
<div class="scroll"><table><tr><th>โมเดล</th>{''.join(f'<th class="n">{esc(k.replace("attack_", "").replace("_awid3", " AWID3"))}</th>' for k in aw_keys)}</tr>{aw_rows}</table></div>
<p class="note">โมเดลที่แจ้งเตือนช่วงโจมตีก็แจ้งเตือนช่วง "ปกติ" ของ AWID3 ด้วยในอัตราใกล้กัน — AWID3 เป็นเครือข่ายทดลองที่ต่างจากของเรา (ปริมาณเฟรม, จำนวนอุปกรณ์, PMF)
จึงถูกมองว่าผิดปกติทั้งชุด ไม่ได้บอกว่าโมเดลเข้าใจการโจมตี — ไม่นำมาใช้ตัดสิน</p>

<h2>7. ข้อจำกัด</h2>
<ul>
<li>การโจมตีเป็นการจำลองที่ระดับฟีเจอร์ การโจมตีจริงอาจกระทบฟีเจอร์อื่นร่วมด้วย (retry, signal, จำนวนอุปกรณ์) ซึ่งน่าจะทำให้จับง่ายขึ้น — ควรยืนยันด้วยการทดสอบโจมตีจริงแบบควบคุมในโซนที่ได้รับอนุญาต</li>
<li>ข้อมูลทั้งหมดมาจากจุดติดตั้งเดียว ช่องเดียว · ช่วง train อยู่ก่อน valid/test ประมาณ 2–4 สัปดาห์</li>
<li>"แจ้งผิด" นับทุกเหตุการณ์บนข้อมูลที่ถือว่าปกติ ถ้ามีเหตุการณ์ผิดปกติจริงที่กฎ B ไม่จับ จะถูกนับเป็นแจ้งผิดด้วย</li>
<li>Autoencoder, LOF และ GMM ใช้ข้อมูล fit บางส่วน (40,000–100,000 แถว) เพื่อให้รันบนเครื่อง sensor ได้</li>
</ul>

<h2>8. การตัดสินใจและสิ่งที่เปลี่ยนในระบบ</h2>
<p><b>เลือก Ensemble</b> เพราะจับได้ใกล้เคียง GMM ตัวเดียว ({pct(gmm['mean_det_cal_synthetic'])}) แต่แจ้งผิดบนข้อมูลใหม่น้อยกว่าครึ่ง
({ens['test_fa_per_h_calibrated']:.2f} เทียบกับ {gmm['test_fa_per_h_calibrated']:.2f} ครั้ง/ชม.), AUC สูงสุด, และครอบคลุมการโจมตีที่ GMM พลาด (RTS/CTS flood) ด้วย ECOD
· Autoencoder จับแบบเบาได้ดีที่สุดเล็กน้อย ({pct(R['Autoencoder MLP 36-16-6-16-36 (log)']['mean_det_cal_weak'])}) แต่จับ beacon/RTS flood ไม่ได้และ fit ช้ากว่า</p>
<table><tr><th>ส่วน</th><th>เดิม</th><th>ใหม่</th></tr>
<tr><td>ตัวตรวจ A</td><td>Isolation Forest 300 ต้น × 256 แถว บนค่าดิบ</td><td>Ensemble: GMM 8 กลุ่ม + Robust z + ECOD บน log + robust scale, รวมด้วย percentile สูงสุด, รายงานเป็น rarity = −log10(1 − percentile)</td></tr>
<tr><td>Threshold</td><td>percentile 99.5 ของข้อมูลเทรน</td><td>ค่าต่ำสุดที่แจ้งผิด ≤ 1 เหตุการณ์/ชม. บน 7 วันล่าสุดที่ไม่ได้ใช้ fit</td></tr>
<tr><td>รอบเทรน</td><td>ทุก 10 นาที (บล็อกการทำงาน)</td><td>ทุก 1 ชั่วโมง บน thread แยก (fit ~2–3 นาทีบน sensor)</td></tr>
<tr><td>ตัวตรวจ B (กฎ)</td><td colspan="2">ไม่เปลี่ยน — ยังจำเป็นสำหรับ evil twin, ARP spoofing, deauth ปลอม</td></tr></table>
<p class="note">ตรวจซ้ำบนสำเนาข้อมูลจริงหลังเปลี่ยน: threshold ตั้งจาก 161 ชั่วโมงที่ไม่ได้ใช้ fit · deauth flood 30/วินาที จับได้ 100% · assoc flood 5/วินาที 100% · probe flood 200/วินาที 100%
· deauth ปลอม 1 เฟรม 8% (กฎ B จับได้ตั้งแต่ครั้งแรก)</p>

<h2>9. ทำซ้ำได้อย่างไร</h2>
<pre class="card" style="white-space:pre-wrap;font-size:12.5px">cd mo_app
python analysis/compare_unsupervised_cache.py captures/monitor/features.csv &lt;work&gt;
python analysis/compare_unsupervised.py &lt;work&gt; &lt;model_c/test_vectors&gt;            # ตารางผล → &lt;work&gt;/results_*.json
python analysis/compare_unsupervised_evidence.py &lt;work&gt; &lt;model_c/test_vectors&gt;   # กราฟเส้นและข้อมูลประกอบ → &lt;work&gt;/evidence.json
# คัดลอกผลไป analysis/reports/unsupervised_results.json และ unsupervised_evidence.json แล้ว
python analysis/make_unsupervised_report.py                                          # → analysis/reports/unsupervised_comparison.html</pre>
<p class="note">seed 0 ทุกขั้นตอน · scikit-learn 1.9.1 · ผลดิบอยู่ใน <code>analysis/reports/unsupervised_results.json</code> และ <code>unsupervised_evidence.json</code></p>
</main></body></html>"""
open(OUT, "w").write(page)
print("wrote", OUT, len(page) // 1024, "KB")
