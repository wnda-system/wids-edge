# Wireless Network Data Collection and Analysis System

โปรเจคนี้เป็นระบบสำหรับ **เก็บข้อมูลเครือข่ายไร้สาย (Wi-Fi)**  โดยใช้ **Mini PC** ทำหน้าที่เป็นเครื่อง **Wi-Fi Monitor Mode Sniffer**  เพื่อดักจับ packet จากอากาศ และบันทึกข้อมูลออกมาในรูปแบบไฟล์ **CSV**  สำหรับนำไปวิเคราะห์ต่อ เช่น monitoring, analysis หรือ machine learning

---

## Project Overview

ระบบนี้ถูกออกแบบมาเพื่อรันบน **Mini PC (Ubuntu Server)**  ที่ติดตั้ง **USB Wi-Fi Adapter ซึ่งรองรับ Monitor Mode**

Mini PC จะทำหน้าที่:
- ดักจับ Wi-Fi packet จากอากาศ (ไม่ต้องเชื่อมต่อ AP)
- อ่านข้อมูลจาก Radiotap และ 802.11 frame
- แปลงข้อมูลเป็นโครงสร้างที่ใช้งานได้
- บันทึกข้อมูลเป็นไฟล์ CSV แบบต่อเนื่อง

เหมาะสำหรับ:
- Wi-Fi monitoring
- Network analysis
- Research / Experiment
- Data collection สำหรับ ML / AI

---

## What You Get From This Project

หลังจากรันระบบ คุณจะได้:
- ข้อมูล Wi-Fi packet ระดับ Monitor Mode
- Metadata จาก Radiotap เช่น RSSI, Channel, Frequency, MCS
- ข้อมูล MAC / BSSID / Frame type
- ไฟล์ CSV ที่สามารถนำไป:
  - เปิดใน Excel / Pandas
  - ทำ Dashboard
  - วิเคราะห์คุณภาพเครือข่าย
  - ใช้เป็น dataset

---

## Project Structure

```text
wifi-sniffer/
├── src/ # โค้ด Python สำหรับ sniff และ parse packet
├── data/ # ข้อมูลที่ได้หลังจากรันโค้ด (CSV)
├── logs/ # log การทำงานของระบบ
└── README.md
```

---

## Folder Description

### src/
โฟลเดอร์สำหรับเก็บ **source code**

ตัวอย่างไฟล์:
- `sniff.py` – สคริปต์หลักสำหรับ:
  - จับ Wi-Fi packet
  - parse Radiotap / Dot11
  - บันทึกข้อมูลลง CSV

**วิธีรันโค้ด**
```bash
cd src
sudo python3 sniff.py
```

---

### data/

โฟลเดอร์สำหรับเก็บ ข้อมูลที่ได้หลังจากรันโค้ด

ลักษณะไฟล์:
- `wifi_packets_YYYYMMDD_HHMMSS.csv`

ข้อมูลภายใน CSV เช่น:

- timestamp
- channel / frequency
- RSSI
- BSSID / MAC address
- frame type / subtype
- QoS / retry flag

---

### logs/

โฟลเดอร์สำหรับเก็บ log การทำงานของระบบ

ใช้สำหรับ:

- debug ปัญหา
- ตรวจสอบสถานะการรัน
- เก็บ error หรือ warning ในอนาคต

---

## Requirements

- Ubuntu Server
- Mini PC
- USB Wi-Fi Adapter (รองรับ Monitor Mode)
- Python 3
- Scapy

ติดตั้ง Scapy:

```bash
sudo apt install python3-scapy
```
---

## Notes

- ระบบนี้ใช้ Monitor Mode ดังนั้น Wi-Fi interface จะไม่เชื่อมต่อกับ AP
- ข้อมูลบาง field อาจว่าง (None) ขึ้นกับชนิด frame และ driver ของ Wi-Fi adapter
- แนะนำให้ปิด wpa_supplicant เพื่อป้องกัน interface down เอง

---
## Author
Project developed by

*Naran Wongvuttisaroj*
*Boonyapon Boontub*

---

## Future Improvements

- Run as systemd service (auto start on boot)
- Real-time dashboard
- API export
- Data aggregation / filtering
- Machine learning pipeline