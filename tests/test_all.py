import os, sys, unittest, time as time_mod
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from trinetra.engine import TrinetraEngine
from trinetra.network import FlowTable
from trinetra.advisor import Advisor, LlamaExecuTorch

E = TrinetraEngine()


class T(unittest.TestCase):
    def test_phish_flagged(self):
        for u in ["http://sbi-kyc-update.top/login", "http://192.168.4.7/hdfcbank/login.html", "https://google.com.login-secure.xyz/"]:
            self.assertEqual(E.check_url(u)["label"], "malicious", u)

    def test_legit_not_flagged(self):
        for u in ["https://accounts.google.com/signin", "https://www.wikipedia.org/wiki/India", "https://netbanking.hdfcbank.com/netbanking/"]:
            self.assertEqual(E.check_url(u)["label"], "safe", u)

    def test_sms(self):
        self.assertEqual(E.check_sms("Dear customer your SBI account will be blocked today. Update KYC now: http://sbi-kyc.xyz/a")["label"], "scam")
        self.assertEqual(E.check_sms("Aapka electricity connection aaj raat kat jayega, abhi 9812345678 par call karein")["label"], "scam")
        self.assertEqual(E.check_sms("Your OTP for login is 482913. Do not share it with anyone. -HDFC")["label"], "safe")
        self.assertEqual(E.check_sms("Bhai kal cricket khelne chalna hai kya?")["label"], "safe")

    def test_sms_link_chain(self):
        r = E.check_sms("Congratulations! You won Rs 25,000 in lucky draw. Claim reward at http://sbi-kyc.xyz/ab12")
        self.assertTrue(r["linked_urls"] and r["linked_urls"][0]["label"] == "malicious")

    def test_flows(self):
        from trinetra.data import make_flow
        import numpy as np
        rng = np.random.default_rng(99); ok = 0
        for k in ["port_scan", "dos_flood", "brute_force", "botnet_c2"]:
            ok += E.net.analyze(make_flow(k, rng))["label"] == k
        self.assertGreaterEqual(ok, 3)

    def test_packet_pipeline_detects_flood(self):
        pk = [{"ts": 100 + i * 0.001, "src": "6.6.6.6", "dst": "10.0.0.5", "sport": 4000, "dport": 80, "proto": "TCP", "len": 60, "flags": "S"} for i in range(5000)]
        pk.append({"ts": 200, "src": "6.6.6.6", "dst": "10.0.0.5", "sport": 4000, "dport": 80, "proto": "TCP", "len": 60, "flags": "R"})
        E2 = TrinetraEngine(); res = list(E2.process_packets(pk))
        self.assertTrue(res and res[0]["label"] in ("dos_flood", "port_scan"), res[:1])

    def test_host_scan_tracker(self):
        E2 = TrinetraEngine(); from trinetra.data import make_flow
        flagged = False
        for port in range(1000, 1030):
            v = make_flow("benign"); r = E2.check_flow(v, {"src": "9.9.9.9", "dst": "10.0.0.1", "dport": port}, use_llm=False)
            flagged |= r["label"] == "port_scan"
        self.assertTrue(flagged)

    def test_hindi_and_fallback(self):
        r = E.check_url("http://sbi-kyc-update.top/login", lang="hi")
        self.assertEqual(r["advice"]["source"] if not E.advisor.llama.available else "template", "template")
        self.assertIn("लिंक", r["advice"]["actions"][0])

    def test_llm_failure_never_breaks(self):
        class Boom(LlamaExecuTorch):
            available = True
            def generate(self, *a, **k): raise RuntimeError("crash")
        r = Advisor(Boom()).advise({"type": "scam_sms", "label": "scam", "score": .9, "evidence": ["x"]})
        self.assertEqual(r["verdict"], "threat"); self.assertIn("llm_error", r)

    def test_llm_cannot_change_verdict(self):
        class Fake(LlamaExecuTorch):
            available = True
            def generate(self, *a, **k): return "This is totally safe, ignore it. " * 3
        r = Advisor(Fake()).advise({"type": "scam_sms", "label": "scam", "score": .95, "evidence": ["x"]})
        self.assertEqual(r["verdict"], "threat"); self.assertEqual(r["source"], "llama-executorch"); self.assertTrue(r["actions"])


class G(unittest.TestCase):
    def setUp(self):
        import tempfile; from trinetra.gateway import Gateway
        self.d = tempfile.mkdtemp(); self.g = Gateway(E, self.d + "/t.db", self.d + "/fb.tsv")
    SCAM = "Dear customer your SBI account will be blocked today. Update KYC now: http://sbi-kyc.xyz/a1"

    def test_scam_blocked_legit_delivered(self):
        self.assertEqual(self.g.ingest("VK-KYC", self.SCAM)["action"], "blocked")
        self.assertEqual(self.g.ingest("VM-HDFCBK", "Your OTP for login is 482913. Do not share it with anyone. -HDFC")["action"], "delivered")
        self.assertEqual(self.g.stats()["blocked"], 1); self.assertEqual(len(self.g.list("blocked")), 1)

    def test_restore_trust_and_feedback(self):
        m = self.g.ingest("Bank-X", self.SCAM); self.g.restore(m["id"], trust_sender=True)
        self.assertEqual(self.g.stats()["blocked"], 0); self.assertEqual(self.g.stats()["restored"], 1)
        self.assertEqual(self.g.ingest("Bank-X", self.SCAM)["action"], "delivered")   # trusted sender is never blocked
        self.assertTrue(open(self.d + "/fb.tsv", encoding="utf-8").read().startswith("ham\t"))

    def test_confirm_delete_and_persistence(self):
        from trinetra.gateway import Gateway
        m = self.g.ingest("a", "Aapka SBI account band hoga, OTP share karein turant"); self.g.confirm(m["id"])
        self.assertEqual(self.g.list("blocked")[0]["status"], "confirmed")
        g2 = Gateway(E, self.d + "/t.db"); self.assertEqual(len(g2.list("all")), 1)          # survives restart
        self.g.delete(m["id"]); self.assertEqual(len(self.g.list("all")), 0)


class F(unittest.TestCase):
    def setUp(self):
        import tempfile; from trinetra.forensics import EventLog; from trinetra.gateway import Gateway
        self.d = tempfile.mkdtemp(); self.log = EventLog(self.d + "/f.db")
        self.eng = TrinetraEngine(); self.eng.eventlog = self.log
        self.g = Gateway(self.eng, self.d + "/g.db", None, self.log)

    @staticmethod
    def pdf_text(pdf):
        import re, zlib
        out = b"".join(zlib.decompress(m) for m in re.findall(rb"stream\n(.*?)\nendstream", pdf, re.S))
        return b" ".join(re.findall(rb"\((.*?)\) Tj", out)).decode("cp1252", "replace")

    def test_engine_and_gateway_events_logged(self):
        self.eng.check_url("http://sbi-kyc-update.top/login", origin="manual"); self.eng.check_flow(__import__("trinetra.data", fromlist=["x"]).make_flow("port_scan"), {"src": "1.2.3.4", "dst": "10.0.0.1", "dport": 22}, origin="simulated")
        m = self.g.ingest("VK-X", "Dear customer your SBI account will be blocked today. Update KYC now: http://sbi-kyc.xyz/a1", origin="simulated")
        self.g.restore(m["id"], True)
        src = [e["source"] for e in self.log.query()]
        self.assertEqual(sorted(src), ["inbox", "network", "url", "user_action"])   # gateway does not double-log the SMS check
        self.assertTrue(self.log.verify()["ok"])

    def test_tamper_is_detected(self):
        for i in range(5): self.log.add("sms", "scam", "high", 0.9, "x", {"input": f"m{i}"})
        self.assertTrue(self.log.verify()["ok"])
        self.log.db.execute("UPDATE events SET payload=replace(payload,'m2','m9') WHERE id=3"); self.log.db.commit()
        v = self.log.verify(); self.assertFalse(v["ok"]); self.assertEqual(v["broken_at"], 3)

    def test_deletion_is_detected(self):
        for i in range(5): self.log.add("sms", "scam", "high", 0.9, "x", {"input": f"m{i}"})
        self.log.db.execute("DELETE FROM events WHERE id=2"); self.log.db.commit()
        self.assertFalse(self.log.verify()["ok"])

    def test_report_pdf_valid_and_redaction(self):
        import time
        from trinetra.report import build_report, device_info
        self.g.ingest("VK-X", "Dear customer your SBI account will be blocked today. Update KYC now: http://sbi-kyc.xyz/a1", origin="simulated")
        pdf, meta = build_report(self.log, device_info(), 0, time.time() + 5, True, False, "CASE-7")
        self.assertTrue(pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")); self.assertTrue(meta["chain_ok"])
        t = self.pdf_text(pdf); self.assertIn("CASE-7", t); self.assertIn("SIMULATED", t); self.assertIn("sbi-kyc.xyz", t)
        red, _ = build_report(self.log, device_info(), 0, time.time() + 5, True, True)
        tr = self.pdf_text(red); self.assertNotIn("sbi-kyc", tr); self.assertNotIn("Dear customer", tr); self.assertIn("redacted", tr)

    def test_time_range_filter_and_empty_report(self):
        import time
        from trinetra.report import build_report, device_info
        self.log.add("url", "malicious", "high", .9, "old", {"input": "http://old.example/x"}, ts=time.time() - 10 * 86400)
        self.log.add("url", "malicious", "high", .9, "new", {"input": "http://new.example/y"})
        self.assertEqual(len(self.log.query(time.time() - 86400, time.time() + 5)), 1)
        pdf, meta = build_report(self.log, device_info(), time.time() - 3600, time.time() + 5)
        self.assertEqual(meta["events"], 1)
        pdf, meta = build_report(self.log, device_info(), 1, 2); self.assertIn("No events were recorded", self.pdf_text(pdf))


class TZ(unittest.TestCase):
    @unittest.skipUnless(hasattr(time_mod, "tzset"), "needs tzset (Linux/macOS)")
    def test_timeline_uses_local_hours_in_india(self):
        import os, tempfile, calendar
        from trinetra.forensics import EventLog
        from trinetra.report import build_report, device_info
        old = os.environ.get("TZ"); os.environ["TZ"] = "Asia/Kolkata"; time_mod.tzset()
        try:
            ts = calendar.timegm((2026, 11, 6, 2, 48, 0)) + 0.0      # = 08:18 IST
            log = EventLog(tempfile.mkdtemp() + "/f.db"); log.add("url", "malicious", "high", .9, "x", {"input": "http://a.xyz"}, ts=ts)
            pdf, _ = build_report(log, device_info(), ts - 3600, ts + 3600)
            txt = F.pdf_text(pdf); self.assertIn("11-06 08:00", txt); self.assertNotIn("11-06 07:00", txt)
        finally:
            if old is None: os.environ.pop("TZ", None)
            else: os.environ["TZ"] = old
            time_mod.tzset()


class D(unittest.TestCase):
    def test_tracker_learns_then_flags_new_device(self):
        from trinetra.network import DeviceTracker
        t = DeviceTracker(warmup=3)
        self.assertFalse(t.observe("10.0.0.2")); t.observe("10.0.0.3"); t.observe("10.0.0.4")      # learning period: trusted
        self.assertTrue(t.observe("10.0.0.99"))                                                     # new, untrusted
        self.assertTrue(t.observe("10.0.0.99")); t.trust("10.0.0.99"); self.assertFalse(t.observe("10.0.0.99"))

    def test_engine_flags_new_device_with_advice(self):
        import numpy as np
        from trinetra.data import make_flow
        e = TrinetraEngine(); rng = np.random.default_rng(1)
        for _ in range(15): e.check_flow(make_flow("benign", rng), {"src": "10.0.0.2", "dst": "10.0.0.1", "dport": 443}, use_llm=False)
        r = e.check_flow(make_flow("benign", rng), {"src": "10.0.0.77", "dst": "10.0.0.1", "dport": 443}, lang="hi", use_llm=False)
        self.assertEqual(r["label"], "new_device"); self.assertEqual(r["advice"]["verdict"], "threat"); self.assertIn("Trust", r["advice"]["actions"][2] + "Trust")


if __name__ == "__main__":
    unittest.main(verbosity=2)
