#!/usr/bin/env python3
"""Trinetra dashboard server (stdlib only - no Flask needed, runs on Pi / Android Termux).
   python app/server.py --port 8080      then open http://<device-ip>:8080"""
import argparse, json, os, platform, sys, random, time
from urllib.parse import urlparse, parse_qs
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from trinetra.engine import TrinetraEngine
from trinetra.data import make_flow, FLOW_CLASSES
from trinetra import __version__
from trinetra.gateway import Gateway
from trinetra.forensics import EventLog
from trinetra.report import build_report, device_info

ENGINE = TrinetraEngine()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE.devices.attach(os.path.join(ROOT, "data", "devices.json"))
EVENTS = EventLog(os.path.join(ROOT, "data", "forensic_log.db")); ENGINE.eventlog = EVENTS   # append-only, hash-chained
GATE = Gateway(ENGINE, os.path.join(ROOT, "data", "trinetra.db"), os.path.join(ROOT, "data", "feedback.tsv"), EVENTS)
if GATE.stats()["total"] == 0: GATE.seed_demo()   # never show an empty dashboard on first run
KNOWN = [f"10.0.0.{i}" for i in (2, 5, 8, 12, 20)]   # the simulated home devices
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code); self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/api/messages": return self._send(200, GATE.list(q.get("view", "inbox"), q.get("lang", "en")))
        if u.path == "/api/events/summary":
            a, b = float(q.get("from", 0)), float(q.get("to", time.time())); return self._send(200, {**EVENTS.counts(a, b), **EVENTS.head()})
        if u.path == "/api/forensic/verify": return self._send(200, EVENTS.verify())
        if u.path == "/api/report.pdf":
            a, b = float(q.get("from", 0)), float(q.get("to", time.time())); case = q.get("case", "")[:120]
            pdf, meta = build_report(EVENTS, device_info(ENGINE.advisor.mode), a, b, q.get("safe") == "1", q.get("redact") == "1", case)
            EVENTS.add("user_action", "report_generated", "none", 0.0, f"forensic report {meta['report_id']} generated",
                       {"action": "report_generated", "report_id": meta["report_id"], "from": a, "to": b, "origin": "live", "case": case})
            self.send_response(200); self.send_header("Content-Type", "application/pdf"); self.send_header("Content-Length", str(len(pdf)))
            self.send_header("Content-Disposition", f'attachment; filename="Trinetra_report_{time.strftime("%Y%m%d_%H%M")}_{meta["report_id"]}.pdf"')
            self.end_headers(); return self.wfile.write(pdf)
        if u.path == "/api/overview":
            now = time.time(); ev = EVENTS.query(now - 86400, now + 1); thr = [e for e in ev if e["severity"] != "none"]
            hours, cats = [0] * 24, {}
            for e in thr:
                hours[min(23, int((e["ts"] - (now - 86400)) // 3600))] += 1; cats[e["label"]] = cats.get(e["label"], 0) + 1
            recent = [{"time": time.strftime("%H:%M:%S", time.localtime(e["ts"])), "source": e["source"], "label": e["label"], "severity": e["severity"],
                       "summary": e["summary"], "origin": e["detail"].get("origin", "api")} for e in ev[-12:][::-1]]
            return self._send(200, {"total": len(ev), "threats": len(thr), "hours": hours, "cats": cats, "recent": recent, "stats": GATE.stats()})
        if u.path == "/api/system":
            mdir = os.path.join(ROOT, "models"); mach = platform.machine()
            kb = round(sum(os.path.getsize(os.path.join(mdir, f)) for f in os.listdir(mdir) if f.endswith(".joblib")) / 1024)
            try:
                with open(os.path.join(mdir, "metrics.json")) as fh: met = json.load(fh)
            except Exception: met = {}
            return self._send(200, {"machine": mach, "arm": mach.lower() in ("aarch64", "arm64") or mach.lower().startswith("armv"), "platform": platform.system() + " " + platform.release(),
                "python": platform.python_version(), "version": __version__, "advisor": ENGINE.advisor.mode, "llama": ENGINE.advisor.llama.available, "models_kb": kb,
                "data": {k: met.get(k, {}).get("data", "unknown") for k in ("scam_sms", "phishing_url", "network_flow")}, "events": EVENTS.head()["count"]})
        if u.path == "/api/devices": return self._send(200, ENGINE.devices.list())
        if u.path == "/api/guard": return self._send(200, {"stats": GATE.stats(), "settings": GATE.settings(), "trusted": GATE.trusted()})
        if self.path in ("/", "/index.html"):
            return self._send(200, open(os.path.join(STATIC, "index.html"), "rb").read(), "text/html")
        if self.path == "/api/status": return self._send(200, ENGINE.status())
        if self.path == "/api/history": return self._send(200, ENGINE.history[-50:][::-1])
        self._send(404, {"error": "not found"})

    def do_POST(self):
        try:
            d = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            lang = d.get("lang", "en"); llm = d.get("use_llm", True)
            if self.path == "/api/url": return self._send(200, ENGINE.check_url(d["text"][:2000], lang, llm, origin="manual"))
            if self.path == "/api/sms": return self._send(200, ENGINE.check_sms(d["text"][:1000], lang, llm, origin="manual"))
            if self.path == "/api/incoming":   # any source (Android app, SMS forwarder, email poller) posts here
                return self._send(200, GATE.ingest(d.get("sender", "unknown")[:60], d["text"][:2000], d.get("channel", "sms"), lang, d.get("origin", "api")))
            if self.path == "/api/demo/incoming":
                sd, tx, ch = GATE.demo_message(float(d.get("scam_ratio", 0.5))); return self._send(200, GATE.ingest(sd, tx, ch, lang, "simulated"))
            if self.path == "/api/message/restore": return self._send(200, GATE.restore(int(d["id"]), bool(d.get("trust_sender"))))
            if self.path == "/api/message/confirm": return self._send(200, GATE.confirm(int(d["id"])))
            if self.path == "/api/message/delete": return self._send(200, GATE.delete(int(d["id"])))
            if self.path == "/api/device/trust": ENGINE.devices.trust(d["ip"]); return self._send(200, {"ok": True})
            if self.path == "/api/untrust": GATE.untrust(d["sender"]); return self._send(200, {"ok": True})
            if self.path == "/api/guard/settings": return self._send(200, GATE.set_settings(d.get("block_threshold"), d.get("warn_threshold")))
            if self.path == "/api/demo/seed": GATE.seed_demo(lang); return self._send(200, GATE.stats())
            if self.path == "/api/guard/clear": GATE.clear(); return self._send(200, {"ok": True})
            if self.path == "/api/simulate":  # synthetic live flow for demos (judges don't need root/pcap)
                kind = d.get("kind") or random.choice(FLOW_CLASSES)
                meta = {"src": random.choice(KNOWN) if random.random() < .85 else f"10.0.0.{random.randint(30, 250)}", "dst": "192.168.1.10", "dport": 0}
                vec = make_flow(kind); meta["dport"] = int(vec[-1])
                r = ENGINE.check_flow(vec, meta, lang, llm, origin="simulated"); r["simulated_kind"] = kind
                return self._send(200, r)
            self._send(404, {"error": "not found"})
        except Exception as e:
            self._send(400, {"error": str(e)})

    def log_message(self, *a): pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--host", default="127.0.0.1", help="use 0.0.0.0 only on a trusted network (no login protection)"); ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args()
    print(f"Trinetra on http://{a.host}:{a.port}  | advisor mode: {ENGINE.advisor.mode}  | cloud calls: none")
    srv = ThreadingHTTPServer((a.host, a.port), H)
    try: srv.serve_forever()
    except KeyboardInterrupt: print("\nTrinetra stopped. Your data is saved in the data/ folder.")   # Ctrl+C is a normal way to quit
    finally: srv.server_close()
