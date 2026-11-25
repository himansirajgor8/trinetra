#!/usr/bin/env bash
# Raspberry Pi 5 (64-bit Raspberry Pi OS) setup. Works the same on Arm Linux / Android Termux (use `pkg` instead of apt).
set -e
sudo apt-get update && sudo apt-get install -y python3-pip python3-venv libpcap-dev
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && pip install scapy
python scripts/train_all.py && python tests/test_all.py
echo "Run dashboard:  python app/server.py --port 8080"
echo "Live capture (root): sudo .venv/bin/python scripts/live_monitor.py --iface eth0"
