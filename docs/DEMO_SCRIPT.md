# Demo video script (target 4:30 – 5:00)
Record screen + a webcam shot of the Pi 5 (power LED, no Ethernet cable if possible to prove offline).
| Time | Show | Say (key message) |
|---|---|---|
| 0:00 | Title card + problem | "Phishing & UPI/KYC scams hit millions of Indians; cloud filters leak private data and fail offline." |
| 0:20 | Pi 5 on desk, **Wi-Fi off**, `ifconfig` | "Everything you'll see runs on this Raspberry Pi 5, fully offline." |
| 0:40 | Architecture slide | Fast detectors decide; **Llama via ExecuTorch** explains; LLM can't change verdict. |
| 1:10 | Dashboard: KYC phishing URL → HIGH, then google.com/signin → safe | Evidence + allow-list = no false alarms. |
| 1:50 | Scam SMS (English), then **Hinglish** electricity-cut scam, toggle **हिन्दी** | Plain-language Hindi advice, 1930 helpline. |
| 2:20 | **Inbox Guard**: press Auto feed -> scams land in *Blocked*, normal messages in *Inbox*; restore one + trust sender | "Nothing is lost: a wrongly blocked message can be restored, and the system learns from it." |
| 2:25 | **Forensic report**: choose *Last 24 hours*, add a case no., click *Generate PDF*, open it; click *Verify log integrity* | "If a device is hacked, an investigator gets a tamper-evident timeline in one click." |
| 2:30 | Real OTP SMS → safe | Low false-positive. |
| 2:45 | Terminal: `python scripts/live_monitor.py` + run `nmap -sS` / `hping3` from a laptop | Real intrusion detected live, with remediation. |
| 3:30 | Dashboard badge "Llama via ExecuTorch", show explanation | Separate pipelines; Hailo (if used) documented. |
| 3:50 | `python scripts/benchmark.py` output | ms latency, KB models, MB RAM on Arm. |
| 4:20 | Impact + roadmap (Android app, more languages) | Close. |
