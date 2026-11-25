"""TrinetraEngine: one entry point for URL / SMS / network analysis + advice. 100% local."""
from __future__ import annotations
import os, time
from .phishing import PhishingDetector
from .sms import SMSDetector
from .network import NetworkDetector, FlowTable, HostTracker, DeviceTracker
from .advisor import Advisor

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")


def ensure_models(model_dir: str = MODEL_DIR):
    """Saved scikit-learn models are NOT portable across versions. If the models are missing or were built with a
    different scikit-learn than the one installed here, retrain automatically (~20 s) instead of crashing."""
    import subprocess, sys, sklearn
    need = ("phishing.joblib", "sms.joblib", "network.joblib"); vf = os.path.join(model_dir, "sklearn_version.txt")
    try:
        with open(vf) as fh: same = fh.read().strip() == sklearn.__version__
    except OSError: same = False
    if same and all(os.path.exists(os.path.join(model_dir, f)) for f in need): return
    root = os.path.dirname(os.path.abspath(model_dir)); cmd = [sys.executable, os.path.join(root, "scripts", "train_all.py"), "--out", model_dir]
    for flag, rel in (("--sms-tsv", "SMSSpamCollection"), ("--feedback-tsv", "feedback.tsv")):
        f = os.path.join(root, "data", rel)
        if os.path.exists(f): cmd += [flag, f]
    print(f"[Trinetra] Models missing or built with another scikit-learn (this machine: {sklearn.__version__}). Training now, ~20 s...", flush=True)
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
    print("[Trinetra] Models ready.", flush=True)


class TrinetraEngine:
    def __init__(self, model_dir: str = MODEL_DIR, advisor: Advisor | None = None):
        ensure_models(model_dir)
        self.url = PhishingDetector.load(os.path.join(model_dir, "phishing.joblib"))
        self.sms = SMSDetector.load(os.path.join(model_dir, "sms.joblib"))
        self.net = NetworkDetector.load(os.path.join(model_dir, "network.joblib"))
        self.advisor = advisor or Advisor()
        self.flows, self.hosts, self.devices = FlowTable(), HostTracker(), DeviceTracker()
        self.history = []; self.eventlog = None   # set to a forensics.EventLog to record every finding

    def _log_event(self, out, origin):
        src = {"phishing_url": "url", "scam_sms": "sms", "network_flow": "network"}[out["type"]]
        det = {"evidence": out.get("evidence", []), "actions": out["advice"]["actions"], "origin": origin}
        if src in ("url", "sms"): det["input"] = out["input"]
        if src == "sms": det["urls"] = out.get("urls", [])
        if src == "network": det.update(src=out.get("src"), dst=out.get("dst"), dport=out.get("dport"), confidence=out.get("confidence"))
        self.eventlog.add(src, out["label"], out["advice"]["severity"], out["score"], out["advice"]["title"], det)

    def _finish(self, finding, lang, use_llm=True, origin="api", log=True):
        t0 = time.perf_counter()
        advice = self.advisor.advise(finding, lang, use_llm)
        out = {**finding, "advice": advice, "advice_ms": round((time.perf_counter() - t0) * 1000, 1),
               "time": time.strftime("%H:%M:%S")}
        self.history.append(out); self.history = self.history[-200:]
        if log and self.eventlog: self._log_event(out, origin)
        return out

    def check_url(self, url, lang="en", use_llm=True, origin="api", log=True):
        t0 = time.perf_counter(); f = self.url.analyze(url); f["detect_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        return self._finish(f, lang, use_llm, origin, log)

    def check_sms(self, text, lang="en", use_llm=True, origin="api", log=True):
        t0 = time.perf_counter(); f = self.sms.analyze(text); f["detect_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        out = self._finish(f, lang, use_llm, origin, log)
        # chain: any link inside an SMS is also run through the URL detector
        out["linked_urls"] = [self.url.analyze(u) for u in f["urls"]]
        return out

    def check_flow(self, vec, meta=None, lang="en", use_llm=True, origin="api", log=True):
        t0 = time.perf_counter(); f = self.net.analyze(vec, meta); f["detect_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        if meta and f["label"] == "benign":  # host-level scan check
            scan, n = self.hosts.update(meta.get("src"), meta.get("dst"), meta.get("dport"), time.time())
            if scan:
                f.update(label="port_scan", score=0.95, evidence=[f"this host probed {n} different ports within 10 seconds"])
        if meta and meta.get("src") and self.devices.observe(meta["src"]) and f["label"] == "benign":   # unfamiliar device on the network
            f.update(label="new_device", score=0.7, evidence=[f"first time this device ({meta['src']}) has been seen on the network"])
        return self._finish(f, lang, use_llm, origin, log)

    def process_packets(self, packets, lang="en"):
        """Feed packet dicts; yields advised findings for every closed flow that is not benign."""
        for p in packets:
            if self.flows.add(p): flows = [self.flows.finish_key(p)]
            else: flows = self.flows.pop_ready(p["ts"])
            for fl in flows:
                r = self.check_flow(fl["features"], {"src": fl["src"], "dst": fl["dst"], "dport": fl["dport"]}, lang, use_llm=False, origin="live")
                if r["advice"]["verdict"] == "threat": yield r

    def status(self):
        return {"advisor_mode": self.advisor.mode, "events": len(self.history),
                "threats": sum(1 for h in self.history if h["advice"]["verdict"] == "threat"), "offline": True}
