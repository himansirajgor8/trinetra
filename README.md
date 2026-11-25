# 🛡️ Trinetra (त्रिनेत्र) — Offline AI Security Assistant for Arm Edge Devices
*The third eye that sees what others miss: three AI "eyes" — links, messages and network traffic — watching over you, entirely on your own device.*
**Bharat AI-SoC Challenge (2nd ed.) · Theme: Cybersecurity & Digital Safety · Problem: On-device threat, phishing and scam detection**

Trinetra detects **network intrusions, phishing URLs and scam SMS** and explains each threat **in plain English or Hindi**,
with recommended remediation — all **on the device, with zero cloud calls**.

## Status (honest)
Working and tested on an x86-64 Windows laptop, fully offline: scam-SMS, phishing-URL, network and unknown-device detection; English/Hindi explanations; Inbox Guard; tamper-evident forensic PDF reports; dashboard; 21 tests. **Not done in this phase:** running Llama through ExecuTorch (explanations are templates; the integration code is written but untested end-to-end), testing on a physical Arm device, and real-data evaluation of the phishing/network detectors. See `docs/TECHNICAL_REPORT.md` section 0.

**Windows quick start (PowerShell):** `pip install -r requirements.txt`, then `python app/server.py --port 8080`, then open http://127.0.0.1:8080 (first start trains the models, about 20 s).

## Focus: one main use case, done well
**Main use case: scam SMS + phishing links** (Inbox Guard + Scanner). Network monitoring (attack classes + unknown-device detection) and the forensic report are supporting modules built on the same pipeline.

## Which model runs where
| Component | Model | Runs on | Runtime |
|---|---|---|---|
| Scam SMS | TF-IDF + Logistic Regression | Arm CPU | scikit-learn |
| Phishing links | Random Forest, 19 features | Arm CPU | scikit-learn |
| Network + unknown devices | Random Forest + Isolation Forest + device tracker | Arm CPU | scikit-learn |
| Plain-language explanation | Llama 3.2 1B Instruct (4-bit) | Arm CPU | **ExecuTorch** (XNNPACK) |
| NPU / accelerator | not used (optional Hailo = separate pipeline, `docs/HAILO.md`) | - | - |

## Deploy on Raspberry Pi 5 / Arm Linux
```bash
git clone <your repo> trinetra && cd trinetra
./run.sh --port 8080              # creates .venv, installs, trains models on first run (~20 s), starts the dashboard
sudo cp deploy/trinetra.service /etc/systemd/system/ && sudo systemctl enable --now trinetra   # optional auto-start (edit paths first)
python scripts/benchmark.py 3000  # latency / size / RAM + sustained-run drift, CPU and temperature on the device -> docs/benchmark_result.json
```
Disconnect the network before recording the demo to prove it works offline.

> Trinetra gives an automated risk assessment and can be wrong. It guides decisions; it does not guarantee detection.

## Architecture
```
 SMS text ──► SMS detector (TF-IDF+LR + rules) ──┐          ┌─► curated remediation playbook (EN/हिन्दी)
 URL ───────► Phishing detector (RF, 19 feats) ──┼─► finding ┤
 Packets ───► FlowTable ► Net detector (RF+IsoForest) + HostTracker ┘   (verdict + evidence + score)
                                                       │
                                                       ▼
                         Llama 3.2 (ExecuTorch, Arm CPU) writes ONLY the plain-language explanation
                         (template fallback if model absent; LLM can never change the verdict)
 Optional, separate pipeline:  Hailo NPU via HailoRT  (docs/HAILO.md)
```
**Why this design wins on the rubric:** tiny classical models do the fast, reliable detection (1–15 ms, <0.5 MB);
Llama on ExecuTorch is used where an LLM is actually strong — explaining & advising non-experts — so the system stays
fast, auditable and safe even on a CPU-only Raspberry Pi 5.

## Features
- **Forensic report (PDF for any time range)**: every detection, block and user action is saved in an **append-only, hash-chained event log** (`data/forensic_log.db`). In the dashboard pick *From / To* (or Last hour / 24 h / 7 days / All), add an optional case/FIR number, tick *redact message text* if you will share it, and download a PDF with: device & period details, **log-integrity check** (detects edited or deleted events), executive summary and timeline, every threat with evidence + SHA-256 + event hash, user actions, recommended next steps and limitations. Demo/simulated events are clearly labelled so they can't be mistaken for a real incident. Sample: `docs/SAMPLE_FORENSIC_REPORT.pdf`. API: `GET /api/report.pdf?from=<epoch>&to=<epoch>&safe=0|1&redact=0|1&case=...`
- **Inbox Guard (auto-block + quarantine)**: every incoming SMS/email is scored automatically — *delivered*, *warned* (red banner) or *blocked* (quarantined). The dashboard shows a full **block history** where you can **restore** a wrongly-blocked message, **trust the sender**, **confirm** it as scam, or delete it. Corrections are saved to `data/feedback.tsv` and used for retraining (`--feedback-tsv`). Feed it from anything via `POST /api/incoming {"sender","text","channel"}` (Android SMS listener, Termux, IMAP poller).
- **Phishing URLs**: 19 lexical/brand-impersonation features, official-domain allow-list (no false alarms on real login pages), no DNS/WHOIS/fetch → private & air-gap safe
- **Scam SMS**: English + **Hinglish** (UPI, KYC, electricity-cut, parcel, lottery scams), explainable top terms, links inside SMS are auto-chained to the URL detector
- **Network IDS**: flow features (CICIDS-style) → Random Forest for 4 attack classes + **Isolation Forest for zero-day anomalies** + cross-flow port-scan tracker; live scapy capture or pcap replay
- **Plain-language advisor** in **English & हिन्दी**; India-specific actions (1930 / cybercrime.gov.in)
- **Resilient**: LLM crash/timeouts never break detection (tested)
- **Dashboard** (stdlib only) for demo, works from any browser on the LAN

> **First run trains the models automatically (~20 s)** and re-trains if you change scikit-learn versions — no manual step needed.

## Quick start (any Arm64/x86 Linux, Pi 5, Termux)
```bash
pip install -r requirements.txt
python scripts/train_all.py --sms-tsv data/SMSSpamCollection   # ~20 s, writes models/*.joblib (synthetic bootstrap data, no downloads)
python tests/test_all.py             # 10 tests
python scripts/demo.py               # terminal demo
python app/server.py --port 8080     # dashboard -> http://localhost:8080 (this device only)
python app/server.py --host 0.0.0.0  # optional: open to your LAN (e.g. view from a phone) - no password, trusted network only
python scripts/benchmark.py          # latency / size / RAM on YOUR device
```
## Use real datasets (SMS already done: UCI data is in `data/`; real held-out F1 0.958, FPR 0%)
```bash
python scripts/train_all.py --phish-csv verified_online.csv --benign-urls top-1m.csv \
       --sms-tsv SMSSpamCollection --cicids-csv Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
```
(Sources: PhishTank / OpenPhish, UCI SMS Spam Collection, CICIDS2017 CSVs. NSL-KDD/UNSW-NB15 need a column mapper like `load_cicids_csv`.)

## Enable Llama via ExecuTorch (required by the challenge)
See `scripts/export_llama_executorch.sh`. Then set `TRINETRA_LLAMA_BIN / _MODEL / _TOKENIZER`; the dashboard badge switches
from *template fallback* to *Llama via ExecuTorch*. Hailo, if used, is a separate pipeline (`docs/HAILO.md`).

## Live IDS
`sudo python scripts/live_monitor.py --iface eth0` · or replay: `python scripts/live_monitor.py --pcap file.pcap`

## Repo map
`trinetra/` core library · `app/` dashboard · `scripts/` train/benchmark/demo/export · `tests/` · `docs/` report, demo script, Hailo notes · `models/` trained artifacts
