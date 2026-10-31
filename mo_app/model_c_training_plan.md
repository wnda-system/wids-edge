# แผนงาน: เทรนและให้บริการโมเดลตรวจจับการโจมตี (Model C) จาก AWID3 — v2

เอกสารนี้สำหรับ **session บนเครื่องเทรน (A100)** อ่านแล้วทำตามได้โดยไม่ต้องรู้บริบทอื่น
**v2 (2026-10-13) แทนที่ v1 ทั้งหมด** (v1 = `README.md` ใน `model_c_bundle.tar.gz`):
โมเดล **รันบนเครื่อง A100** เป็น HTTP service; เครื่อง sensor ส่งฟีเจอร์รายวินาทีมาถามทุก 5 วินาที
→ **ทำตามข้อ 6 (สัญญา API) อย่างเคร่งครัด** เพราะเครื่อง sensor จะเขียนตัวเรียกตามสัญญานี้

---

## 0. บริบทสั้นๆ

- เครื่อง sensor: Ubuntu, Celeron N4000, USB WiFi RTL8822BU ใน monitor mode, ฟังช่อง **100 (5500 MHz) HT40+**
  ในมหาวิทยาลัย (SSID: KUWIN, KUWIN-IOT, eduroam, AIS ×2; AP Cisco); IP บน KUWIN `<mini-pc-ip>`
- เครือข่ายส่วนใหญ่ **เข้ารหัส** → เห็นแค่ชั้น MAC/radiotap; ชั้น app เห็นเฉพาะเครือข่ายเปิด
- มีตัวตรวจอยู่แล้วบน sensor: **A** Isolation Forest, **B** กฎ (ดู `docs/detection_rules.md`)
- **Model C (งานนี้)** = classifier แบบ supervised บอก **ประเภทการโจมตี + ความน่าจะเป็น ราย 1 วินาที**
- เครื่อง sensor เข้าถึงเครื่องนี้ได้ที่ `<hpc-host>` (ทดสอบแล้วด้วย SSH)
- **ปัญหาหลักไม่ใช่กำลังเครื่อง แต่คือสภาพแวดล้อมต่างกัน** (domain shift):
  AWID3 = ห้องทดลอง ~16 เครื่อง, **เปิด PMF (802.11w)**, adapter/ช่องของเขา;
  ของเรา = มหาวิทยาลัยจริง หลายร้อยเครื่อง, ส่วนใหญ่ **ไม่เปิด PMF** (หลัง deauth เครื่องหลุดจริงแล้วต่อใหม่), adapter จับ beacon ได้ ~30–40%
  → โมเดลที่ใหญ่/ซับซ้อนขึ้นมักจำ "ลายนิ้วมือห้องทดลอง" มากขึ้น ไม่ได้ดีขึ้นกับเครือข่ายเรา

## 1. สิ่งที่ได้รับจากเครื่อง sensor

`~/experiment_1/model_c_bundle.tar.gz` (ส่งแล้ว) — แตกไฟล์แล้วได้ `model_c_bundle/`:

| path | คืออะไร |
|---|---|
| `code/capture.py` | `extract_fields(pkt, ...)` ดึง 163 คอลัมน์ต่อ frame จาก scapy packet (**ห้ามแก้**) |
| `code/analysis/features.py` | `clean()`, `load()`, `windows()` → ฟีเจอร์รายวินาที 36 ตัว, `FEATURE_VERSION = 2` (**ห้ามแก้**) |
| `code/analysis/detector.py`, `anomaly_detect.py` | ตัวตรวจ A/B (อ้างอิง) |
| `docs/` | `detection_rules.md`, `anomaly_detection_notes.md`, plan v1 |
| `ours/features.csv` | **ฟีเจอร์รายวินาทีของ traffic ปกติในสถานที่จริง** 351,180 วินาที (~4 วัน, v2) — ใช้วัดการแจ้งผิด |
| `ours/raw/*.csv.gz` | frame ดิบ 163 คอลัมน์ 1 วัน (287 ไฟล์ × 5 นาที) |
| `ours/context.json` | SSID/BSSID ที่รู้จัก, SSID ที่ป้องกัน |
| `env.txt` | เวอร์ชัน library ของ sensor |

**`ours/` มี MAC/IP ของอุปกรณ์จริง** — ใช้ภายในทีมเท่านั้น

## 2. เตรียมเครื่อง

1. Python 3.12 venv สำหรับโค้ดดึงค่า: **scapy 2.7.0, numpy 2.5.3, pandas 3.0.6** (ให้ผล `extract_fields`/`windows` ตรงกับ sensor)
   library สำหรับโมเดลเลือกได้อิสระ (XGBoost/LightGBM GPU, PyTorch ฯลฯ) — **บันทึกเวอร์ชันทั้งหมดใน `report.md`**
2. AWID3: https://icsdweb.aegean.gr/awid/download — **ใช้ pcap** (ข้อ 3)
   เอาเฉพาะชั้น MAC: `Deauth`, `Disas`, `(Re)Assoc`, `RogueAP`, `Evil_Twin`, `Krack`, `Kr00k` + traffic ปกติให้มากพอ; ถ้ามีที่: `SSDP`
   ข้าม (ต้องถอดรหัส payload ซึ่ง sensor ทำไม่ได้): Botnet, Malware, SSH, SQL_Injection, Website_spoofing
3. **ตรวจโครงสร้างไฟล์ AWID3 จริงก่อนเขียนโค้ด** (ชื่อไฟล์, pcap กับ CSV/label จับคู่กันยังไง, ชื่อคอลัมน์ label) — อย่าเดา; สรุปให้ผู้ใช้ดูก่อนเริ่มเขียนโค้ด

## 3. แปลง AWID3 pcap → ฟีเจอร์รายวินาที + label

1. อ่าน pcap ด้วย scapy `PcapReader` (stream) → `extract_fields(pkt, frame_number, first_time, prev_time, state, llc_snap_dispatch=True)`
   ต่อ frame (ดูวิธีเรียกใน `capture.py → CaptureSession.run()`) → เขียน `.csv.gz` ทีละไฟล์ (ใช้หลาย process ได้)
2. **label ระดับ frame** จากไฟล์ label ของ AWID3: จับคู่ด้วย `frame.number` + ตรวจซ้ำด้วย `frame.time_epoch`
   (จับคู่ไม่ครบ 100% → หยุดและรายงาน)
3. `features.windows(df, 1, known_pairs, arp_seed)` **ทีละไฟล์**
   - `known_pairs`: (SSID, BSSID) ของ AP จริงใน AWID3 จากส่วน **normal** เท่านั้น (ไม่งั้น `new_bssid_known_ssid` เป็น 0 ตลอด)
   - `arp_seed`: IP→MAC จากส่วน normal (แบบ `monitor.py → import_baselines`)
   - ตัดวินาทีแรก/สุดท้ายของแต่ละไฟล์
4. **label รายวินาที:** มี frame โจมตี ≥ 1 frame = ประเภทนั้น (หลายประเภท → ที่มี frame มากสุด), ไม่มี = `normal`

## 4. ฟีเจอร์

**ห้ามใช้** (ขึ้นกับสถานที่/อุปกรณ์/จำนวนคน): `signal_mean`, `signal_std`, `len_mean`, `bssid_signal_range`,
`n_sa`, `n_dest_mac`, `n_ssid`, `n_bssid`, ค่าดิบของ `frames`/`mgmt`/`ctrl`/`data`, ทุกคอลัมน์ระดับ frame (MAC, SSID, channel, rate, เวลา)

**เริ่มจาก:** `deauth`, `disassoc`, `auth`, `assoc_req`, `deauth_to_one_client_10s`, `deauth_seq_out_of_order`,
`tsf_offset_switches`, `new_bssid_known_ssid`, `max_bssid_per_ssid`, `bssid_beacon_rate`, `arp_ip_mac_flips_10s`,
`arp_ips_per_mac_60s`, `arp_reply_ratio`, `retry_ratio`, `protected_ratio`
+ **สัดส่วน**: `mgmt/frames`, `ctrl/frames`, `data/frames`, `deauth/mgmt`, `beacon/mgmt`, `probe_req/mgmt`, `rts/ctrl`, `cts/ctrl`

- ฟีเจอร์เพิ่มเติมต้องคำนวณจาก **ผลของ `windows()` (36 คอลัมน์) เท่านั้น** เพราะ sensor ส่งมาแค่นั้น (ข้อ 6)
  ถ้าจำเป็นต้องใช้ข้อมูลระดับ frame (เช่น EAPOL ต่อวินาทีสำหรับ Krack) → **ห้ามทำเอง** ให้ระบุใน `report.md`
  ว่าต้องการฟีเจอร์อะไร แล้วเครื่อง sensor จะเพิ่มใน `windows()` + bump `FEATURE_VERSION`
- ตรวจทุกฟีเจอร์: เทียบการกระจายช่วง normal ของ AWID3 กับ `ours/features.csv` — ต่างกันมาก = ขึ้นกับสภาพแวดล้อม → ตัดหรือแปลงเป็นสัดส่วน

## 5. โมเดล — เทียบหลายตัว แล้วเลือกด้วยเกณฑ์เดียว

**เกณฑ์ตัดสิน (ใช้ตัวนี้ตัวเดียว ไม่ใช้ accuracy):**
> recall ต่อประเภทบน AWID3 held-out **หลังตั้ง threshold ให้แจ้งผิดบนข้อมูลของเรา ≤ 1 เหตุการณ์/ชั่วโมง** (รวมทุกประเภท)

เทรนอย่างน้อย:

| ระดับ | โมเดล | หมายเหตุ |
|---|---|---|
| ฐาน | Logistic Regression (scaled) | ถ้าใกล้เคียงตัวอื่น (ต่าง ≤ 3 จุด) → **เลือกตัวนี้** (ใช้กับสภาพแวดล้อมใหม่ได้ดีสุด) |
| **หลัก** | Gradient Boosting (XGBoost/LightGBM GPU หรือ sklearn HistGradientBoosting) | ใส่ **monotonic constraint** ให้ฟีเจอร์ที่บ่งชี้การโจมตี (ยิ่งมาก prob การโจมตีนั้นต้องไม่ลด) — กันกรณีผู้โจมตีจริงยิงเร็วกว่าที่ AWID3 มี; `class_weight`/`scale_pos_weight` สำหรับข้อมูลไม่สมดุล; ปรับเทียบความน่าจะเป็น (calibration) ด้วยข้อมูล validation |
| ทดลอง | โมเดลลำดับเวลา (Temporal CNN / GRU / Transformer เล็ก) บนฟีเจอร์รายวินาทีย้อนหลัง **≤ 60 วินาที** | จับลำดับ เช่น deauth → ต่อใหม่เป็นชุด, Krack/Kr00k; **ใช้เฉพาะถ้าชนะตัวหลักชัดเจนบนเกณฑ์ข้างบน** |

**ไม่ทำ:** deep learning ระดับ frame (header ทุก frame) — ได้ผลบน AWID3 สูงแต่จำลายนิ้วมือห้องทดลอง ใช้กับเราไม่ได้

ขั้นตอนประเมิน:
1. **แบ่งตามไฟล์/ช่วงเวลา ไม่สุ่มรายวินาที** (train / validation / test)
2. **AWID3 held-out:** precision / recall / F1 ต่อประเภท + confusion matrix
3. **ข้อมูลปกติของเรา (`ours/features.csv`)** — ทุกวินาทีเป็น normal:
   ครึ่งแรก (ตามเวลา) ใช้ **ตั้ง threshold ต่อประเภท**, ครึ่งหลังใช้ **วัด** แจ้งผิดกี่เหตุการณ์/ชั่วโมง
   (วินาทีติดกันห่าง ≤ 3 วินาที = 1 เหตุการณ์) แยกตามประเภทและช่วงเวลาของวัน
4. **เกณฑ์ผ่าน:** recall ≥ 0.9 สำหรับ Deauth, Disas, (Re)Assoc, Evil_Twin, RogueAP (หลังใช้ threshold) และแจ้งผิดบนข้อมูลของเรา (ครึ่งหลัง) ≤ 1/ชม.
   Krack / Kr00k / SSDP รายงานตามจริง — ไม่ผ่านก็ส่งได้ แต่เขียนตามจริงใน `report.md`
5. ดู feature importance / SHAP — ถ้าฟีเจอร์สำคัญไม่สมเหตุสมผลกับการโจมตีนั้น ให้สงสัยว่าเรียนรู้สภาพแวดล้อม และรายงาน

## 6. สัญญา API (ห้ามเปลี่ยนรูปแบบ)

HTTP service บนเครื่อง A100, เข้าถึงจาก sensor ที่ `http://<hpc-host>:<port>` (แนะนำ 8500; ระบุ port จริงใน `report.md`)

**การยืนยันตัวตน:** header `Authorization: Bearer <token>` — สร้าง token สุ่มยาว ≥ 32 ตัวอักษร
เก็บในไฟล์ (ไม่ใส่ใน git/report) แล้วให้ผู้ใช้นำไปใส่ที่เครื่อง sensor เอง; request ที่ไม่มี/ผิด token → 401

**ข้อมูลที่ sensor ส่งเป็นแค่ตัวเลขฟีเจอร์ 36 ตัว + เวลา — ไม่มี MAC/IP/SSID**

### `GET /v1/info`
```json
{
  "model": "awid3-mac-v1",
  "feature_version": 2,
  "context_seconds": 60,
  "classes": ["normal", "Deauth", "Disas", "..."],
  "thresholds": {"Deauth": 0.8, "...": 0.0},
  "class_to_alert_type": {"Deauth": "Deauthentication attack (Model C)", "...": "..."}
}
```
`context_seconds` = จำนวนวินาทีย้อนหลังที่โมเดลต้องใช้ (0 ถ้าใช้แค่วินาทีนั้น, สูงสุด 60)

### `POST /v1/predict`
request:
```json
{
  "sensor_id": "momoparadise-ch100",
  "feature_version": 2,
  "windows": [
    {"win": 1791523495, "features": {"frames": 187.0, "mgmt": 40.0, "...": 0.0}},
    "... เรียงตามเวลา: context_seconds วินาทีก่อนหน้า + วินาทีใหม่ที่ต้องการผล ..."
  ],
  "predict_from": 1791523550
}
```
- `features` = **36 คอลัมน์ของ `windows()` (FEATURE_VERSION 2) ครบทุกตัว ชื่อเดิม** — server เป็นคนแปลงเป็นฟีเจอร์ของโมเดลเอง
- `predict_from` = ขอผลเฉพาะวินาที `win >= predict_from`; วินาทีก่อนหน้าส่งมาเป็น context เท่านั้น
- วินาทีที่ขาดหาย (gap) → server เติม 0 เอง; `feature_version` ไม่ตรง → 409
- **server ต้องไม่มี state ข้าม request** (ทุกอย่างที่ต้องใช้อยู่ใน request) — server restart ได้โดย sensor ไม่ต้องรู้

response:
```json
{
  "model": "awid3-mac-v1",
  "results": [
    {"win": 1791523550, "proba": {"normal": 0.98, "Deauth": 0.01, "...": 0.0},
     "predicted": "normal", "alert": false}
  ]
}
```
- `alert = true` เมื่อมีประเภท X ≠ `normal` ที่ `proba[X] >= thresholds[X]`; `predicted` = ประเภทที่ proba สูงสุดในกลุ่มที่ผ่าน (ไม่ผ่านเลย → `normal`)
- เวลาตอบ < 1 วินาที สำหรับ request ~70 วินาที; sensor เรียกทุก 5 วินาที

### `GET /v1/health` → `{"ok": true, "model": "..."}`

## 7. สิ่งที่ต้องส่งมอบ (ใน `~/experiment_1/model_c/`)

```
model_c/
  service/               # โค้ด service + วิธีรัน (systemd unit หรือ docker) ให้เปิดเองหลังรีบูต
  model/                 # ไฟล์โมเดล + meta (เวอร์ชัน library ทุกตัว)
  report.md              # ผลข้อ 5 ทั้งหมด, โครงสร้าง AWID3 ที่พบ (ข้อ 2.3), port, ข้อจำกัด, ฟีเจอร์ที่อยากให้ sensor เพิ่ม
  test_vectors/
    request_*.json       # request ตัวอย่าง: วินาทีปกติจาก ours/features.csv + วินาทีโจมตีจาก AWID3
    response_*.json      # response ที่ service ตอบจริง
```
`test_vectors` ใช้ให้เครื่อง sensor ยิง request เดียวกันแล้วเทียบว่าได้ผลเหมือนกัน (ยืนยันว่าเชื่อมกันถูก)

## 8. ฝั่งเครื่อง sensor (ทำหลังได้ service — ไม่ต้องทำบนเครื่องนี้)

1. ยิง `test_vectors` จาก sensor → ผลต้องตรง
2. Live Monitor เรียก `/v1/predict` ทุก 5 วินาที (ส่ง context + วินาทีใหม่), timeout 2 วินาที;
   service ล่ม/เครือข่ายหลุด → Model C หยุดชั่วคราว **A/B ทำงานต่อตามปกติ** + แสดงสถานะบน dashboard
3. **Shadow mode ≥ 3 วัน:** บันทึกผลแต่ยังไม่แจ้งเตือน / ไม่มีผลต่อการเทรน A/B → วัดแจ้งผิดจริงทุกช่วงเวลา (รวมเช้าวันทำงาน)
4. ทดสอบการจับ: แทรก frame โจมตีลงข้อมูลจริง (`anomaly_detect.py`) + ถ้าได้รับอนุญาต: ทดลองโจมตีจริงด้วย AP ทดสอบของเราเอง
   (ข้อมูลที่ได้ส่งกลับมาเทรนเพิ่มได้ — แก้ domain shift ได้ตรงที่สุด)
5. ผ่านแล้วเปิดแจ้งเตือน: ระดับ `model C` แสดงประเภท + ความน่าจะเป็นบน dashboard

## 9. สิ่งที่ห้ามทำ

- ห้ามใช้ CSV ของ AWID3 เป็นฟีเจอร์ตรงๆ / ห้ามใช้ฟีเจอร์ชั้น app ที่ต้องถอดรหัส
- ห้ามแก้ `capture.py` / `features.py` และห้ามใช้ข้อมูลอื่นนอกจาก 36 คอลัมน์ของ `windows()` เป็น input ของ service
- ห้ามสุ่มแบ่ง train/test รายวินาที / ห้ามตั้ง threshold แล้ววัดแจ้งผิดบนข้อมูลชุดเดียวกัน
- ห้ามเปิด service โดยไม่มี token / ห้ามใส่ token ใน report หรือ git
- ห้ามรายงานผลที่ไม่ได้รันจริง — ทำไม่ได้หรือไม่ผ่านเกณฑ์ ให้เขียนตามจริงใน `report.md`
