"""Inbox Guard: automatic block / warn / deliver policy with a reviewable quarantine.

Any source can feed it (Android SMS listener, Termux SMS forwarder, email IMAP poller, or the dashboard simulator)
through Gateway.ingest(). Nothing is ever silently lost: blocked messages sit in quarantine where the user can
restore them ("Not scam"), optionally trust the sender, confirm them as scam, or delete them.
User corrections are written to data/feedback.tsv in UCI format so the model can be retrained on them
(python scripts/train_all.py --feedback-tsv data/feedback.tsv ...).

Policy (thresholds adjustable in the dashboard):
    trusted sender                -> delivered (still scored, never blocked)
    score >= block_threshold(.85) -> BLOCKED  (quarantined, not shown in inbox)
    score >= warn_threshold (.50) -> WARNED   (delivered with a red warning banner)
    otherwise                     -> delivered
"""
from __future__ import annotations
import json, os, random, re, sqlite3, threading, time
from .data import _fill, SPAM_T, HAM_T
from .advisor import PLAYBOOK

DEFAULTS = {"block_threshold": 0.85, "warn_threshold": 0.50}

# Realistic demo traffic, including legit messages that LOOK scary (so judges can see restore/false-positive handling)
DEMO_LEGIT = [
    ("VM-HDFCBK", "Your OTP for login is {otp}. Do not share it with anyone. -HDFC"),
    ("AX-SBIUPI", "Rs {amt} debited from a/c XX{otp} on 12-Jan. Not you? Call 1800-1234 -SBI"),
    ("AMAZON", "Your Amazon order has been shipped and will arrive by Friday."),
    ("Mom", "Beta call me when you are free, urgent but nothing serious"),
    ("Rahul", "Bhai kal cricket khelne chalna hai kya?"),
    ("BSES-PWR", "Your electricity bill of Rs {amt} is generated. Pay via official app before due date."),
    ("IRCTC", "Train 12951 is on time. Platform 3."),
    ("DrShah", "Reminder: your appointment with Dr. Shah is on Monday 10am"),
]
DEMO_SCAM_SENDERS = ["+91 98" + "".join(random.choice("0123456789") for _ in range(8)), "VK-KYCINF", "+44 7700 900123", "TX-ALERTS", "+92 300 1234567"]


class Gateway:
    def __init__(self, engine, db_path: str, feedback_path: str | None = None, eventlog=None):
        self.engine, self.feedback_path, self.eventlog = engine, feedback_path, eventlog
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.db = sqlite3.connect(db_path, check_same_thread=False); self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript("""
              CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, sender TEXT, channel TEXT,
                text TEXT, score REAL, label TEXT, evidence TEXT, urls TEXT, action TEXT, status TEXT DEFAULT 'active');
              CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value REAL);
              CREATE TABLE IF NOT EXISTS trusted(sender TEXT PRIMARY KEY, added REAL);""")
            self.db.commit()

    # ---------------------------------------------------------------- settings / trusted senders
    def settings(self):
        with self.lock:
            s = dict(DEFAULTS); s.update({r["key"]: r["value"] for r in self.db.execute("SELECT * FROM settings")})
        return s

    def set_settings(self, block=None, warn=None):
        s = self.settings(); b = float(block if block is not None else s["block_threshold"]); w = float(warn if warn is not None else s["warn_threshold"])
        b = min(max(b, 0.5), 0.99); w = min(max(w, 0.2), b)
        with self.lock:
            self.db.executemany("INSERT OR REPLACE INTO settings VALUES(?,?)", [("block_threshold", b), ("warn_threshold", w)]); self.db.commit()
        return self.settings()

    def trusted(self):
        with self.lock: return [r["sender"] for r in self.db.execute("SELECT sender FROM trusted ORDER BY added DESC")]

    def untrust(self, sender):
        with self.lock: self.db.execute("DELETE FROM trusted WHERE sender=?", (sender,)); self.db.commit()

    def _is_trusted(self, sender):
        with self.lock: return self.db.execute("SELECT 1 FROM trusted WHERE sender=?", (sender,)).fetchone() is not None

    # ---------------------------------------------------------------- core
    def ingest(self, sender: str, text: str, channel: str = "sms", lang: str = "en", origin: str = "api"):
        r = self.engine.check_sms(text, lang, use_llm=False, log=False)   # the gateway logs its own richer inbox event
        score, evidence = float(r["score"]), list(r["evidence"])
        bad_links = [l for l in r.get("linked_urls", []) if l["label"] == "malicious"]
        if bad_links:  # a phishing link inside the message is decisive evidence
            score = max(score, 0.90); evidence.append("contains a link flagged as phishing: " + bad_links[0]["input"][:60])
        s = self.settings(); trusted = self._is_trusted(sender)
        if trusted: action = "delivered"
        elif score >= s["block_threshold"]: action = "blocked"
        elif score >= s["warn_threshold"]: action = "warned"
        else: action = "delivered"
        with self.lock:
            cur = self.db.execute("INSERT INTO messages(ts,sender,channel,text,score,label,evidence,urls,action) VALUES(?,?,?,?,?,?,?,?,?)",
                (time.time(), sender, channel, text, round(score, 4), "scam" if score >= s["warn_threshold"] else "safe",
                 json.dumps(evidence), json.dumps(r["urls"]), action))
            self.db.commit(); mid = cur.lastrowid
        if self.eventlog:
            sev = "high" if action == "blocked" else "medium" if action == "warned" else ("low" if score >= s["warn_threshold"] else "none")
            self.eventlog.add("inbox", action, sev, score, f"{action}: message from {sender}",
                {"sender": sender, "channel": channel, "text": text, "action": action, "evidence": evidence, "urls": r["urls"], "message_id": mid,
                 "block_threshold": s["block_threshold"], "warn_threshold": s["warn_threshold"], "trusted": trusted, "origin": origin,
                 "actions": PLAYBOOK["scam_sms"]["en"] if sev != "none" else []})
        return self.get(mid, lang) | {"trusted_sender": trusted}

    def _row(self, row, lang):
        ev = json.loads(row["evidence"]); finding = {"type": "scam_sms", "label": row["label"], "score": row["score"], "evidence": ev}
        adv = self.engine.advisor.advise(finding, lang, use_llm=False)
        return {"id": row["id"], "time": time.strftime("%d %b %H:%M", time.localtime(row["ts"])), "sender": row["sender"], "channel": row["channel"],
                "text": row["text"], "score": row["score"], "action": row["action"], "status": row["status"], "urls": json.loads(row["urls"]),
                "evidence": adv["evidence_local"], "title": adv["title"], "explanation": adv["explanation"], "actions": adv["actions"], "severity": adv["severity"]}

    def get(self, mid, lang="en"):
        with self.lock: row = self.db.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
        return self._row(row, lang) if row else None

    def list(self, view="inbox", lang="en", limit=100):
        blocked = "action='blocked' AND status IN ('active','confirmed')"
        where = {"blocked": blocked, "inbox": f"NOT ({blocked})", "all": "1=1"}.get(view, "1=1")
        with self.lock: rows = self.db.execute(f"SELECT * FROM messages WHERE {where} ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [self._row(r, lang) for r in rows]

    def stats(self):
        with self.lock:
            q = lambda sql: self.db.execute(sql).fetchone()[0]
            return {"total": q("SELECT COUNT(*) FROM messages"),
                    "blocked": q("SELECT COUNT(*) FROM messages WHERE action='blocked' AND status IN ('active','confirmed')"),
                    "warned": q("SELECT COUNT(*) FROM messages WHERE action='warned' AND status='active'"),
                    "delivered": q("SELECT COUNT(*) FROM messages WHERE action='delivered' AND status!='deleted'"),
                    "restored": q("SELECT COUNT(*) FROM messages WHERE status='restored'"),
                    "trusted_senders": q("SELECT COUNT(*) FROM trusted")}

    # ---------------------------------------------------------------- user actions (human-in-the-loop)
    def _feedback(self, text, label):
        if not self.feedback_path: return
        os.makedirs(os.path.dirname(os.path.abspath(self.feedback_path)), exist_ok=True)
        clean = re.sub(r"\s+", " ", text).strip()
        with open(self.feedback_path, "a", encoding="utf-8") as f: f.write(label + "\t" + clean + "\n")

    def _act(self, action, m, **extra):
        if self.eventlog and m:
            self.eventlog.add("user_action", action, "none", 0.0, f"user {action} message #{m['id']}",
                              {"action": action, "message_id": m["id"], "sender": m["sender"], "text": m["text"], "origin": "live", **extra})

    def restore(self, mid, trust_sender=False):
        """'This is NOT a scam' -> back to inbox, logged as a false positive for retraining."""
        m = self.get(mid)
        if not m: return None
        with self.lock:
            self.db.execute("UPDATE messages SET status='restored' WHERE id=?", (mid,))
            if trust_sender: self.db.execute("INSERT OR REPLACE INTO trusted VALUES(?,?)", (m["sender"], time.time()))
            self.db.commit()
        self._feedback(m["text"], "ham"); self._act("restore", m, trust_sender=bool(trust_sender)); return self.get(mid)

    def confirm(self, mid):
        """'Yes, this is a scam' -> stays/moves to blocked, logged as a true positive."""
        m = self.get(mid)
        if not m: return None
        with self.lock:
            self.db.execute("UPDATE messages SET status='confirmed', action='blocked' WHERE id=?", (mid,)); self.db.commit()
        self._feedback(m["text"], "spam"); self._act("confirm", m); return self.get(mid)

    def delete(self, mid):
        self._act("delete", self.get(mid))
        with self.lock: self.db.execute("DELETE FROM messages WHERE id=?", (mid,)); self.db.commit()
        return {"deleted": mid}

    def clear(self):
        with self.lock: self.db.execute("DELETE FROM messages"); self.db.commit()

    SEED = [
        ("VK-KYCINF", "Dear customer your SBI account will be blocked today. Update KYC now: http://sbi-kyc.xyz/a1", "sms"),
        ("VM-HDFCBK", "Your OTP for login is 482913. Do not share it with anyone. -HDFC", "sms"),
        ("+92 300 1234567", "Congratulations! You won Rs 25,000 in lucky draw. Claim reward at http://bit.ly/x9Kd2a", "sms"),
        ("Mom", "Beta call me when you are free", "sms"),
        ("+91 9812345670", "Aapka electricity connection aaj raat kat jayega, abhi 9812345678 par call karein", "sms"),
        ("AMAZON", "Your Amazon order has been shipped and will arrive by Friday.", "sms"),
        ("TX-ALERTS", "Loan approved Rs 49,999 without documents! Apply instantly http://tinyurl.com/loan77", "sms"),
        ("Rahul", "Bhai kal cricket khelne chalna hai kya?", "sms"),
        ("+91 9876501234", "Aapka SBI account band hoga, OTP share karein turant", "sms"),
        ("BSES-PWR", "Your electricity bill of Rs 1,240 is generated. Pay via official app before due date.", "sms"),
        ("alerts@secure-paytm.verify-account.xyz", "Your Paytm wallet is suspended. Verify now: http://paytm-verify.xyz/login", "email"),
    ]

    def seed_demo(self, lang="en"):
        for sender, text, ch in self.SEED: self.ingest(sender, text, ch, lang, origin="simulated")

    # ---------------------------------------------------------------- demo traffic
    @staticmethod
    def demo_message(scam_ratio=0.5):
        rng = random.Random()
        if rng.random() < scam_ratio:
            return rng.choice(DEMO_SCAM_SENDERS), _fill(rng.choice(SPAM_T), rng), "sms"
        sender, t = rng.choice(DEMO_LEGIT)
        return sender, _fill(t, rng), "sms"
