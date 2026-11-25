#!/usr/bin/env python3
"""Live IDS on a real interface (needs root + scapy), or replay a pcap:  --pcap capture.pcap"""
import argparse, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from trinetra.engine import TrinetraEngine
from trinetra.network import sniff_scapy, read_pcap
ap = argparse.ArgumentParser(); ap.add_argument("--iface"); ap.add_argument("--pcap"); ap.add_argument("--lang", default="en"); a = ap.parse_args()
print("NOTICE: monitor only networks and devices you own or are explicitly authorised to test (use an isolated lab for demos).")
E = TrinetraEngine(); src = read_pcap(a.pcap) if a.pcap else sniff_scapy(a.iface)
print(f"monitoring ({'pcap' if a.pcap else a.iface}) | advisor: {E.advisor.mode}")
for r in E.process_packets(src, a.lang):
    ad = r["advice"]; print(f"[{r['time']}] {ad['severity'].upper()} {ad['title']}: {r.get('src')} -> {r.get('dst')}:{r.get('dport')}\n    " + "\n    ".join(ad["actions"][:2]))
