#!/usr/bin/env python3
"""Edge benchmark: model size, per-inference latency (p50/p95), throughput, peak RSS. Run it ON the target device
(Raspberry Pi 5 / Android Termux) and paste the table into docs/TECHNICAL_REPORT.md."""
import os, sys, time, platform, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np
from trinetra.engine import TrinetraEngine, MODEL_DIR
from trinetra.data import gen_urls, gen_sms, gen_flows

def peak_mb():
    try:
        import resource; return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)   # Linux / Pi / Termux
    except ImportError:
        try:
            import psutil; return round(psutil.Process().memory_info().rss / 1048576, 1)               # Windows (pip install psutil)
        except ImportError: return None


E = TrinetraEngine(); N = 300
urls, _ = gen_urls(N * 2, seed=99); sms, _ = gen_sms(N * 2, seed=98); fl, _ = gen_flows(N, seed=97)


def bench(fn, items):
    fn(items[0]); t = []
    for x in items[:N]:
        s = time.perf_counter(); fn(x); t.append((time.perf_counter() - s) * 1000)
    t = np.array(t); return {"p50_ms": round(float(np.percentile(t, 50)), 2), "p95_ms": round(float(np.percentile(t, 95)), 2),
                             "per_sec": round(1000 / t.mean(), 1)}


R = {"device": platform.platform(), "machine": platform.machine(), "python": platform.python_version(),
     "model_kb": {f: round(os.path.getsize(os.path.join(MODEL_DIR, f)) / 1024, 1) for f in os.listdir(MODEL_DIR) if f.endswith(".joblib")},
     "url": bench(lambda u: E.url.analyze(u), urls), "sms": bench(lambda s: E.sms.analyze(s), sms),
     "flow": bench(lambda v: E.net.analyze(list(v)), list(fl)),
     "end_to_end_sms_with_advice": bench(lambda s: E.check_sms(s, use_llm=False), sms),
     "peak_rss_mb": peak_mb(), "advisor_mode": E.advisor.mode}
if E.advisor.llama.available:
    t = time.time(); E.advisor.advise({"type": "scam_sms", "label": "scam", "score": .95, "evidence": ["asks for OTP"]}); R["llama_advice_s"] = round(time.time() - t, 2); R["llama_stats"] = getattr(E.advisor.llama, "last_stats", None)   # tokens, first-token & end times if the runner reports them
def temp_c():
    import glob
    v = []
    for p in glob.glob("/sys/class/thermal/thermal_zone*/temp"):
        try:
            with open(p) as fh: v.append(int(fh.read()) / 1000)
        except (OSError, ValueError): pass
    return round(max(v), 1) if v else None                         # None where the OS hides it (try Termux:API or a Pi)


SOAK = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 0   # python scripts/benchmark.py 3000  -> sustained run
if SOAK:
    pool = (sms * (SOAK // len(sms) + 1))[:SOAK]; lat = []; m0, c0, w0, t0 = peak_mb(), time.process_time(), time.time(), temp_c()
    for x in pool:
        q = time.perf_counter(); E.sms.analyze(x); lat.append((time.perf_counter() - q) * 1000)
    k = max(len(lat) // 10, 1)
    R["soak"] = {"inferences": SOAK, "p50_first10pct_ms": round(float(np.percentile(lat[:k], 50)), 2), "p50_last10pct_ms": round(float(np.percentile(lat[-k:], 50)), 2),
                 "peak_rss_start_mb": m0, "peak_rss_end_mb": peak_mb(), "cpu_seconds": round(time.process_time() - c0, 2), "wall_seconds": round(time.time() - w0, 2),
                 "temp_start_c": t0, "temp_end_c": temp_c()}
print(json.dumps(R, indent=2)); json.dump(R, open(os.path.join(os.path.dirname(MODEL_DIR), "docs", "benchmark_result.json"), "w"), indent=2)
