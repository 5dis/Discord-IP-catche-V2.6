# 🌐 Network Monitor (Discord / UDP / STUN Analyzer)

A real-time Python tool that monitors network traffic and displays **public IP connections**, with detailed geolocation and ISP information.

> Built for educational network analysis (WebRTC / UDP / STUN traffic).

---

## ⚠️ Disclaimer

This tool only analyzes **network traffic visible on your own machine**.
It does NOT reveal private user identities or bypass encryption.

---

## 🚀 Features

- Real-time network monitoring
- Detects public IP connections
- Shows:
  - Country
  - City
  - ISP
  - Organization
  - ASN
  - Reverse DNS
  - VPN / Hosting detection
- Clean dark terminal UI
- Cache system (faster performance)
- Works with Discord / WebRTC traffic (UDP)

---

## 📦 Installation

### 1. Install Wireshark (required)

Download here:
https://www.wireshark.org/download.html

Make sure to install:
- ✔ TShark
- ✔ Npcap
- ✔ Add to PATH

---

### 2. Install Python dependencies

```bash
pip install -r requirements.txt