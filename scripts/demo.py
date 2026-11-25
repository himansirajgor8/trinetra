#!/usr/bin/env python3
"""Scripted terminal demo (use it while recording the demo video)."""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from trinetra.engine import TrinetraEngine
from trinetra.data import make_flow
E = TrinetraEngine(); C = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[93m", "none": "\033[92m"}; Z = "\033[0m"
def show(r):
    a = r["advice"]; print(f"{C[a['severity']]}[{a['severity'].upper():6}] {a['title']}{Z}  score={r['score']}  ({r['detect_ms']} ms)")
    for e in r["evidence"][:3]: print("   •", e)
    if a["actions"]: print("   → " + a["actions"][0])
    print()
print(f"=== Trinetra | advisor: {E.advisor.mode} | internet: not used ===\n")
print("--- 1. Phishing links ---")
for u in ["http://sbi-kyc-update.top/login", "https://accounts.google.com/signin", "http://192.168.4.7/hdfcbank/login.html"]:
    print(u); show(E.check_url(u))
print("--- 2. Scam SMS (English + Hinglish) ---")
for s in ["Dear customer your SBI account will be blocked today. Update KYC now: http://sbi-kyc.xyz/a1",
          "Aapka electricity connection aaj raat kat jayega, abhi 9812345678 par call karein",
          "Your OTP for login is 482913. Do not share it with anyone. -HDFC"]:
    print(s[:70]); show(E.check_sms(s))
print("--- 3. Network flows ---")
for k in ["benign", "port_scan", "dos_flood", "brute_force", "botnet_c2"]:
    print("flow:", k); show(E.check_flow(make_flow(k), {"src": "10.0.0.66", "dst": "192.168.1.10", "dport": 22}))
