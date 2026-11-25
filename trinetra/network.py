"""Network intrusion detection.
 - FlowTable: packets -> bidirectional flows -> 15 CICIDS-style features
 - NetworkDetector: Random Forest (known attack classes) + Isolation Forest (zero-day anomaly)
 - HostTracker: cross-flow behaviour (one source touching many ports = scan)
Packet records are plain dicts so the pipeline is testable without root/scapy:
  {"ts": float, "src": str, "dst": str, "sport": int, "dport": int, "proto": "TCP", "len": int, "flags": "SA"}"""
from __future__ import annotations
import joblib, json, os, time
from collections import defaultdict, deque
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from .data import FLOW_FEATURES, FLOW_CLASSES


class FlowTable:
    def __init__(self, idle_timeout=15.0):
        self.flows, self.idle = {}, idle_timeout

    @staticmethod
    def _key(p):
        a, b = (p["src"], p["sport"]), (p["dst"], p["dport"])
        return (a, b, p["proto"]) if a <= b else (b, a, p["proto"])

    def add(self, p):
        k = self._key(p); f = self.flows.get(k)
        if f is None:
            f = self.flows[k] = {"src": p["src"], "dst": p["dst"], "dport": p["dport"], "t0": p["ts"], "t1": p["ts"],
                                 "fwd": [], "bwd": [], "ts": [], "syn": 0, "rst": 0, "ack": 0}
        fl = p.get("flags", "")
        f["syn"] += "S" in fl; f["rst"] += "R" in fl; f["ack"] += "A" in fl
        (f["fwd"] if p["src"] == f["src"] else f["bwd"]).append(p["len"])
        f["ts"].append(p["ts"]); f["t1"] = p["ts"]
        return ("F" in fl or "R" in fl)  # True => flow can be closed now

    def pop_ready(self, now):
        done = [k for k, f in self.flows.items() if now - f["t1"] > self.idle]
        return [self.finish(k) for k in done]

    def pop_all(self):
        return [self.finish(k) for k in list(self.flows)]

    def finish_key(self, p): return self.finish(self._key(p))

    def finish(self, k):
        f = self.flows.pop(k)
        allp = f["fwd"] + f["bwd"]; dur = max(f["t1"] - f["t0"], 1e-6); ts = np.sort(f["ts"])
        iat = np.diff(ts) if len(ts) > 1 else np.array([0.0])
        vec = [dur, len(f["fwd"]), len(f["bwd"]), sum(f["fwd"]), sum(f["bwd"]), float(np.mean(allp)), float(np.std(allp)),
               sum(allp) / dur, len(allp) / dur, f["syn"], f["rst"], f["ack"], float(iat.mean()), float(iat.std()), f["dport"]]
        return {"src": f["src"], "dst": f["dst"], "dport": f["dport"], "features": vec, "t1": f["t1"]}


class HostTracker:
    """Flags a source that contacts many distinct ports/hosts in a short window."""
    def __init__(self, window=10.0, port_thresh=20):
        self.w, self.th, self.ev = window, port_thresh, defaultdict(deque)

    def update(self, src, dst, dport, ts):
        q = self.ev[src]; q.append((ts, dst, dport))
        while q and ts - q[0][0] > self.w: q.popleft()
        ports = {d for _, _, d in q}
        return len(ports) >= self.th, len(ports)


def sniff_scapy(iface=None, count=0, timeout=None):
    """Live capture generator via scapy (needs root). Yields packet dicts."""
    from scapy.all import sniff, IP, TCP, UDP  # optional dependency
    import queue; q = queue.Queue()

    def cb(pkt):
        if IP not in pkt: return
        l4 = TCP if TCP in pkt else UDP if UDP in pkt else None
        if l4 is None: return
        q.put({"ts": float(pkt.time), "src": pkt[IP].src, "dst": pkt[IP].dst, "sport": int(pkt[l4].sport),
               "dport": int(pkt[l4].dport), "proto": "TCP" if l4 is TCP else "UDP", "len": len(pkt),
               "flags": str(pkt[TCP].flags) if l4 is TCP else ""})
    import threading
    threading.Thread(target=lambda: sniff(iface=iface, prn=cb, store=False, count=count, timeout=timeout), daemon=True).start()
    while True:
        yield q.get()


def read_pcap(path):
    """Offline pcap replay via scapy (for demos on recorded traffic)."""
    from scapy.all import rdpcap, IP, TCP, UDP
    for pkt in rdpcap(path):
        if IP not in pkt: continue
        l4 = TCP if TCP in pkt else UDP if UDP in pkt else None
        if l4 is None: continue
        yield {"ts": float(pkt.time), "src": pkt[IP].src, "dst": pkt[IP].dst, "sport": int(pkt[l4].sport),
               "dport": int(pkt[l4].dport), "proto": "TCP" if l4 is TCP else "UDP", "len": len(pkt),
               "flags": str(pkt[TCP].flags) if l4 is TCP else ""}


EXPLAIN = {
    "port_scan": ["sent tiny probe packets with almost no replies", "touched many different ports"],
    "dos_flood": ["sent an extreme number of packets in seconds", "almost no responses came back"],
    "brute_force": ["made repeated short login-style attempts", "targeted a login service port (SSH/FTP/RDP/Telnet)"],
    "botnet_c2": ["held a long, regular 'heartbeat' style connection", "used an unusual port typical of remote control"],
}


class NetworkDetector:
    def __init__(self):
        self.rf = None; self.iso = None

    def fit(self, X, y, seed=0):
        self.rf = RandomForestClassifier(n_estimators=40, max_depth=14, n_jobs=-1, random_state=seed).fit(X, y)
        self.iso = IsolationForest(n_estimators=50, contamination=0.02, random_state=seed).fit(X[y == 0])
        return self

    def analyze(self, vec, meta=None, min_conf=0.6):
        x = np.array([vec], dtype=float); pr = self.rf.predict_proba(x)[0]
        cls = self.rf.classes_[int(pr.argmax())]; conf = float(pr.max()); label = FLOW_CLASSES[int(cls)]
        raw = float(self.iso.score_samples(x)[0])      # single pass (predict() would repeat the whole forest)
        anomaly = -raw                                   # higher = more anomalous
        is_anom = raw < self.iso.offset_
        evidence = list(EXPLAIN.get(label, []))
        if label == "benign" and is_anom and conf < 0.9:   # unknown behaviour, flag as suspicious
            label, evidence = "unknown_anomaly", ["behaviour is statistically unusual compared with this network's normal traffic"]
        out = {"type": "network_flow", "label": label, "score": round(1 - float(pr[0]) if label != "unknown_anomaly" else min(anomaly, 1), 4),
               "confidence": round(conf, 4), "anomaly_score": round(anomaly, 4), "evidence": evidence}
        if meta: out.update(meta)
        return out

    def save(self, path): joblib.dump(self, path, compress=3)

    @staticmethod
    def load(path):
        d = joblib.load(path); d.rf.n_jobs = 1; d.iso.n_jobs = 1  # no thread-pool overhead per single flow
        return d


class DeviceTracker:
    """Learns which devices normally appear on the network, then flags unfamiliar ones.
    Devices seen during the first `warmup` flows are trusted automatically (learning period)."""
    def __init__(self, path=None, warmup=15):
        self.path, self.warmup, self.devices, self.seen = None, warmup, {}, 0
        if path: self.attach(path)

    def attach(self, path):
        self.path = path
        try:
            with open(path, encoding="utf-8") as f: self.devices = json.load(f)
            self.seen = self.warmup + 1 if self.devices else 0     # already learned: no auto-trust window
        except (OSError, ValueError): pass

    def save(self):
        if not self.path: return
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f: json.dump(self.devices, f)

    def observe(self, ip, ts=None):
        """Returns True when `ip` is a NEW, not-yet-trusted device."""
        ts = ts or time.time(); self.seen += 1; d = self.devices.get(ip)
        if d: d["flows"] += 1; d["last"] = ts; return not d["trusted"]
        self.devices[ip] = {"first": ts, "last": ts, "flows": 1, "trusted": self.seen <= self.warmup}; self.save()
        return not self.devices[ip]["trusted"]

    def trust(self, ip):
        if ip in self.devices: self.devices[ip]["trusted"] = True; self.save()

    def list(self):
        return [{"ip": ip, "flows": d["flows"], "first": time.strftime("%d %b %H:%M", time.localtime(d["first"])), "trusted": d["trusted"]}
                for ip, d in sorted(self.devices.items(), key=lambda kv: -kv[1]["first"])]
