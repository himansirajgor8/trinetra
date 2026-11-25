---
title: "Trinetra: An Offline, On-Device AI Security Assistant for Arm Edge Hardware"
subtitle: "Technical Report — Bharat AI-SoC Challenge, 2nd Edition (Cybersecurity & Digital Safety)"
---

# 0. Status at submission
**Completed and working (tested on an x86-64 Windows laptop, fully offline):** scam-SMS detector (evaluated on a real public dataset), phishing-URL detector, network-flow and unknown-device detector, plain-language explanations in English and Hindi with remediation steps, Inbox Guard (automatic blocking with restore and sender trust), a tamper-evident event log with PDF forensic reports, a multi-page dashboard, and 21 automated tests.

**Not completed in this phase (stated plainly):**
- **Llama through ExecuTorch was not run.** The integration code and an export script are written, but the explanations in this version come from built-in templates. The detectors, not any language model, make every decision.
- **No test on a physical Arm device.** All measurements are from an x86-64 machine; the design targets the Arm CPU.
- The phishing-URL and network detectors were trained on **synthetic** data, so no real-world accuracy is claimed for them.
- No measured results for Hindi or other Indian-language scams on real data, and the user-understanding test was not carried out.
- The network monitor in the demo uses simulated traffic; live packet capture exists as a separate script and is not yet connected to the dashboard.

# 1. Problem and motivation
Phishing links, KYC/UPI/OTP scam SMS and network intrusions target home users and small businesses, who rarely have a security team and often have patchy internet. Cloud-based filters send private messages and URLs to third parties and stop working offline. Trinetra brings detection **and** human-readable guidance onto a low-cost Arm device, with **no cloud dependency**.

# 2. Requirements coverage
| Requirement | How Trinetra meets it |
|---|---|
| Classify network traffic for anomalies/intrusions | Flow table → Random Forest (port scan, DoS flood, brute force, botnet C2) + Isolation Forest (unknown anomalies) + cross-flow host tracker |
| Detect phishing URLs | 19-feature lexical/brand-impersonation Random Forest + official-domain allow-list; no network lookups |
| Detect scam SMS | Word+char TF-IDF Logistic Regression blended with explainable rules; English and Hinglish |
| Explain threats in plain language | Template explanations in EN/हिन्दी grounded in detector evidence (a Llama layer is implemented but was not run in this phase) |
| Recommend remediation | Curated, India-aware playbook per threat type (e.g. 1930 / cybercrime.gov.in) |
| Local processing only | No outbound calls anywhere in the code path; works air-gapped |
| Llama + ExecuTorch | `LlamaExecuTorch` wrapper around ExecuTorch `llama_main` and an export script are written; **not executed end-to-end in this phase** |

# 3. Architecture
Three detectors emit a common *finding* (type, label, score, evidence). The advisor maps a finding to a title, severity, explanation and actions.

**Separation of duties (safety by design).** Classical models decide the *verdict*. Llama only writes the *explanation* from the supplied evidence, under a system prompt forbidding new facts. Remediation steps come from a curated playbook, so a hallucinating LLM cannot flip a verdict or invent a dangerous instruction. If the LLM is unavailable or crashes, a deterministic template answers and the UI states the source. This is covered by unit tests.

**Pipelines.** Pipeline A: Llama 3.2 Instruct (1B/3B, 4-bit groupwise weights) through ExecuTorch (XNNPACK) on the Arm CPU. Pipeline B (optional): Hailo NPU through HailoRT for compatible vision workloads. They are separate and documented in `docs/HAILO.md`; Llama is never run on the Hailo NPU.

# 4. Methods
**Phishing URL.** Features: length, host length, dots, hyphens, digit ratio, raw-IP host, `@` trick, HTTPS, subdomain depth, host entropy, credential keywords, suspicious TLD, brand-in-host-but-not-official-domain, punycode, path/query length, special characters, shorteners, non-standard port. Model: Random Forest (60 trees). A known-brand official-domain check damps scores, which removed false alarms on genuine sign-in pages during testing.

**Scam SMS.** Numbers, URLs and phone numbers are normalised to tokens so the model learns patterns rather than values. Features: word 1–2-grams + character 2–4-grams (robust to Hinglish spelling variants). Model: class-balanced Logistic Regression. Final score = 0.8·ML + 0.2·rule signal (urgency, credential requests, KYC/blocking threats, prize lures, link, call-back). Top contributing terms and rule hits are returned as evidence. URLs found in an SMS are automatically passed to the URL detector.

**Network.** Packets are aggregated into bidirectional flows with 15 CICIDS-style features (duration, packet/byte counts, packet-length stats, rates, SYN/RST/ACK counts, inter-arrival stats, destination port). Random Forest (40 trees) classifies five classes; an Isolation Forest (50 trees, scored in a single pass) trained on benign flows flags statistically unusual behaviour as *unknown anomaly*. A sliding-window tracker flags one source touching ≥20 ports in 10 s. Capture uses scapy (live or pcap replay); the pipeline itself is dependency-free and testable with plain packet dicts.

# 5. Results
## 5.1 Functional validation
Ten automated tests pass: phishing flagged/legit not flagged (including real sign-in pages), English and Hinglish scam SMS, genuine OTP SMS not flagged, SMS→URL chaining, flow classification, an end-to-end packet-to-alert flood test, host scan tracking, Hindi output, LLM-failure resilience, and LLM-cannot-change-verdict.

## 5.2 Detection metrics
### Scam SMS — REAL data (UCI SMS Spam Collection)
**Data hygiene.** 5,574 raw messages; 437 exact/near-duplicates (case-, space- and digit-insensitive) were removed *before* splitting, leaving 5137. Split 60/20/20 into train (3082), validation (1027) and test (1028). The test set has 904 legitimate and 124 scam messages. Training also uses 1,200+ synthetic India/Hinglish/Hindi messages (the UCI corpus has no Indian scams); synthetic data is **never** used for testing here. Legitimate training examples include realistic bank alerts, UPI notices, OTP messages, delivery updates and KYC reminders so the model does not learn that words like "bank", "OTP" or "KYC" always mean scam.

**Threshold chosen on validation only.** The alert threshold (0.33) is the best-F1 point on the validation set among thresholds with at most 1% false alarms; the test set was used once, for the numbers below.

| Metric (test set, threshold 0.33) | Value |
|---|---|
| Accuracy | 0.9883 |
| Precision | 0.9746 |
| Recall | 0.9274 |
| F1 | 0.9504 |
| False-positive rate (legit flagged as scam) | 0.0033 |
| Confusion matrix [[TN, FP],[FN, TP]] | [[901, 3], [9, 115]] |

**False alarms vs missed scams (test set, for transparency; not used to choose the threshold):**

| Threshold | Precision | Recall | F1 | False alarms | Missed scams |
|---|---|---|---|---|---|
| 0.3 | 0.9664 | 0.9274 | 0.9465 | 4 | 9 |
| 0.4 | 0.9829 | 0.9274 | 0.9544 | 2 | 9 |
| 0.5 | 0.9823 | 0.8952 | 0.9367 | 2 | 13 |
| 0.6 | 0.9909 | 0.879 | 0.9316 | 1 | 15 |
| 0.7 | 0.9894 | 0.75 | 0.8532 | 1 | 31 |
| 0.85 | 1.0 | 0.2419 | 0.3896 | 0 | 94 |

Lowering the threshold catches more scams but raises false alarms; the right setting depends on how costly a wrongly blocked message is, which is why Inbox Guard keeps blocked messages restorable. Limits: UCI messages are older UK/Singapore-style English; accuracy on today's Indian scam wording and on Hindi/regional languages has **not** been measured on real data (the India/Hinglish accuracy of 1.0 is on synthetic messages and only shows the pipeline handles those patterns).

### Phishing URL and network flow — SYNTHETIC data (placeholders)
These two detectors were trained and tested on bundled **synthetic** data so the project runs with no downloads. The numbers only show that the pipeline works; the synthetic classes are easy to separate, so **no real-world accuracy is claimed** for the phishing-URL or network detectors.

| Detector | Data | Accuracy | F1 |
|---|---|---|---|
| Phishing URL | synthetic | 1.0 | 1.0 |
| Network flow (5-class, macro) | synthetic | 0.9995 | 0.9995 |

## 5.3 Edge performance
Measured with `scripts/benchmark.py`. All numbers were measured on an x86-64 development machine (Linux, Python 3.12.3), **not** on Arm hardware. Arm measurements were not completed in this phase.

| Metric | Development machine (x86-64) |
|---|---|
| Phishing model size | 19.1 KB |
| SMS model size | 383.0 KB |
| Network model size | 214.5 KB |
| URL inference p50 / p95 | 2.82 / 3.41 ms |
| SMS inference p50 / p95 | 2.25 / 2.88 ms |
| Flow inference p50 / p95 | 4.41 / 5.11 ms |
| Peak RSS (all models) | 160.3 MB |
| Llama 3.2 1B (ExecuTorch, 4-bit) tokens/s, first-token latency, RAM | not measured (Llama was not run) |

## 5.4 Inbox Guard (automatic blocking with human review)
Incoming messages pass through a three-zone policy: score ≥ 0.85 *blocked* (quarantined), 0.50–0.85 *warned* (delivered with a banner), else *delivered*; thresholds are user-adjustable. Because a wrongly blocked genuine message is costly, blocking is never destructive: every blocked message is kept in a reviewable quarantine, the user can restore it, trust the sender (trusted senders are never blocked) or confirm it as scam, and each correction is logged as a labelled example for retraining. A phishing link found inside a message raises its score (the SMS model and URL model are chained). The state is stored locally in SQLite. Note: in this prototype the feed is simulated or posted to a local API; blocking real phone SMS requires the Android app described in the roadmap.

## 5.5 Forensic activity log and incident report
Every finding from the three detectors, every Inbox Guard decision and every user action (restore / confirm / delete / report generated) is appended to a separate event log. Each event stores SHA-256(previous hash + canonical event content), forming a hash chain; `verify()` recomputes the chain and reports the first event whose content was changed or whose neighbour was removed (covered by unit tests). The dashboard's *Clear* button does not touch this log. A responder chooses a time range and downloads a PDF containing the device/period details, the integrity verdict with chain-head and period-digest hashes, an executive summary with timeline, itemised findings (evidence, SHA-256 of the original text, event hash), user actions, next steps and limitations. An optional redaction mode replaces message text and URLs with a hash and length so the report can be shared without exposing content. Simulated and manually typed test events are labelled in the report. Limits: the chain is tamper-*evident*, not tamper-proof (someone with full file access could rebuild it, so the printed chain-head hash should be recorded off-device); the log records what Trinetra observed, not a forensic image of the device; and Devanagari text prints as '?' in the PDF (the SHA-256 identifies the stored original).

## 5.6 Processor map and design for the judging criteria
Detectors (scikit-learn) and the Llama explainer (ExecuTorch, XNNPACK) are separate pipelines designed to run on the Arm CPU (a design target; not yet run on Arm hardware in this phase); no NPU is used (see `README.md`, "Which model runs where"). The network module also learns the devices normally seen on the network and flags an unfamiliar device as *new_device* until the user trusts it. The dashboard states on every page that assessments can be wrong. **Detection quality:** report precision, recall and false-alarm rate on held-out data (Section 5.2). **On-device performance:** response time and memory measured with `scripts/benchmark.py` on the target device (Section 5.3), including Llama tokens/s, first-token latency and RAM. **User effectiveness:** results of the user-understanding test in `docs/USER_TEST.md` — *not completed in this phase (the test sheet is provided)*.

## 5.7 Deployment configuration
Environment used: x86-64 Windows 10 laptop with 8 GB RAM, Python 3.12, scikit-learn (the models are retrained automatically on first start for the installed version). Not completed in this phase: Llama variant/quantization and ExecuTorch runner configuration, and any Arm device configuration. Planned measurement method for the next phase: `python scripts/benchmark.py 3000` on the Arm device (latency p50/p95, model size, peak RAM, CPU seconds, temperature, latency drift over a sustained run), plus Llama time-to-first-token and tokens per second from the runner.

## 5.8 Data governance, privacy and updates
Only permitted data is used: the UCI SMS Spam Collection (public, CC BY 4.0) and generated synthetic examples; no private inboxes were scraped and no personal data was collected. Any collected examples must be consented and stripped of names, numbers, account identifiers and OTPs. Network capture is only for networks and devices the user owns or is authorised to test. Trinetra stores only what it needs on the device (the event log keeps message text so a report can be produced; redaction is available when sharing). It makes no network calls; there are no online updates, and any future model or rule update would be installed manually and verified before use. Recommendations are advisory: Trinetra never clicks links or takes irreversible actions on its own, and the language model only explains the detector's findings.

# 6. Privacy, safety and ethics
All inference is local; no URLs, messages or packets leave the device. Alerts are advisory: Trinetra never auto-blocks or deletes. The LLM is constrained to explanation. Known limitations are listed below.

# 7. Limitations (honest)
- Bundled models are trained on synthetic bootstrap data; production use requires retraining on real feeds and periodic updates.
- URL detection is lexical only; it cannot see page content, and new brands outside the brand list rely on generic signals.
- Flow-level IDS cannot inspect encrypted payloads; botnet C2 detection depends on timing/port behaviour.
- Scam detection quality in languages other than English/Hinglish is not validated.
- Adversarial evasion (crafted URLs/SMS) is not evaluated.
- Llama through ExecuTorch was not run, so explanations are template-based in this version.
- No testing on a physical Arm device; all measurements are from an x86-64 machine.
- The phishing-URL and network detectors have no real-world evaluation (synthetic data only).
- Real Indian-language (Hindi and regional) scam performance is unmeasured; the SMS test set is an older UK/Singapore-style English dataset.
- The user-understanding test was not carried out.
- Demo network traffic is simulated; live capture is a separate script not yet connected to the dashboard.

# 8. Roadmap
**Next phase:** run a pre-exported Llama 3.2 1B (4-bit) through ExecuTorch for the explanations; test on a physical Arm device (Raspberry Pi 5 or an Arm Android phone) offline and report latency, memory, temperature and stability; train and evaluate the phishing and network detectors on real data; run the user-understanding test; connect live capture to the dashboard.

Further ideas: **Scam-call protection (listed as an example application area in the problem statement; not implemented in this version).** Planned in three steps: (1) number-reputation screening using Android's call-screening role (local blocklist, spoofed/international-prefix patterns, call-burst frequency) — no audio needed; (2) on-device speech-to-text of the call (a small Whisper-class model) feeding transcript chunks to the same scam classifier and Llama explanation to show a live warning such as "caller is asking for an OTP / claims to be police"; (3) a user-reported-call form. Constraints to state plainly: Android generally does not expose the other party's audio to third-party apps, and call recording/analysis has consent and legal implications, so audio would be processed in memory only and never stored.

Android app (SMS listener + URL share-sheet) using the same models through ExecuTorch; more Indian languages; federated, privacy-preserving updates; a Hailo-accelerated visual phishing (QR/page-screenshot) classifier; signed model updates for air-gapped sites.

# 9. Reproducibility
`pip install -r requirements.txt` → `python scripts/train_all.py` → `python tests/test_all.py` → `python app/server.py`. Source layout and commands are in `README.md`.
