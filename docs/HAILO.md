# Hailo (optional) — separate pipeline, clearly documented
Per the challenge rules, accelerators and Llama are **separate pipelines**:

| Pipeline | Runtime | Hardware | Used for |
|---|---|---|---|
| A. Advisor | **ExecuTorch** (`llama_main`, XNNPACK) | Raspberry Pi 5 **Arm CPU** | Llama 3.2 plain-language explanations |
| B. Accelerated detectors (optional) | **HailoRT** (`.hef`) | **Hailo NPU** (AI HAT+ / AI HAT+ 2) | Compatible CNN workloads only, e.g. screenshot/QR-code phishing page classifier or byte-image malware classifier |

Llama does **not** run on the Hailo NPU. The shipped detectors (RF/LR/IsolationForest) are CPU-only by design so the
base solution works on a plain Pi 5 / Android phone. To add Pipeline B: compile a small CNN with the Hailo Dataflow
Compiler -> `.hef`, run via HailoRT Python API, and feed its score into `engine.py` as an extra finding source.
