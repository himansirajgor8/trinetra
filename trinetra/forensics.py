"""Forensic event log: an append-only, hash-chained record of everything Trinetra sees and does.

Every event stores  hash = SHA-256(previous_hash + canonical_payload).  Editing or deleting an old row changes its
hash and breaks every later link, so `verify()` can detect it. This is TAMPER-EVIDENT, not tamper-PROOF: someone with
full write access to the file could rebuild the whole chain. To close that gap, note the chain-head hash printed on each
report somewhere outside the device (email it, print it, write it in the case file).

The log lives in its own file (data/forensic_log.db) and is NOT touched by the dashboard's "Clear" button.
"""
from __future__ import annotations
import hashlib, json, os, sqlite3, threading, time

GENESIS = "0" * 64
SEVERITIES = ("none", "low", "medium", "high")


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


class EventLog:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.path = path
        self.db = sqlite3.connect(path, check_same_thread=False); self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.db.execute("""CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, source TEXT,
                label TEXT, severity TEXT, score REAL, payload TEXT, prev_hash TEXT, hash TEXT)""")
            self.db.execute("CREATE INDEX IF NOT EXISTS ix_ts ON events(ts)"); self.db.commit()

    # ------------------------------------------------------------------ write (append only)
    def add(self, source: str, label: str, severity: str, score: float, summary: str, detail: dict, ts: float | None = None):
        ts = float(ts if ts is not None else time.time()); score = round(float(score), 4)
        payload = json.dumps({"ts": ts, "source": source, "label": label, "severity": severity, "score": score,
                              "summary": summary, "detail": detail}, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        with self.lock:
            row = self.db.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else GENESIS
            h = sha256(prev + payload)
            cur = self.db.execute("INSERT INTO events(ts,source,label,severity,score,payload,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?)",
                                  (ts, source, label, severity, score, payload, prev, h))
            self.db.commit(); return cur.lastrowid

    # ------------------------------------------------------------------ read
    @staticmethod
    def _ev(r):
        p = json.loads(r["payload"])
        return {"id": r["id"], "ts": r["ts"], "source": r["source"], "label": r["label"], "severity": r["severity"],
                "score": r["score"], "summary": p["summary"], "detail": p["detail"], "prev_hash": r["prev_hash"], "hash": r["hash"]}

    def query(self, start: float = 0, end: float | None = None, include_safe: bool = True):
        end = end if end is not None else time.time() + 1
        sql = "SELECT * FROM events WHERE ts>=? AND ts<=?" + ("" if include_safe else " AND (severity!='none' OR source='user_action')") + " ORDER BY id"
        with self.lock: rows = self.db.execute(sql, (start, end)).fetchall()
        return [self._ev(r) for r in rows]

    def counts(self, start: float = 0, end: float | None = None):
        end = end if end is not None else time.time() + 1
        with self.lock:
            tot, thr = self.db.execute("SELECT COUNT(*), SUM(severity!='none') FROM events WHERE ts>=? AND ts<=?", (start, end)).fetchone()
        return {"events": tot or 0, "threats": thr or 0}

    def head(self):
        with self.lock:
            r = self.db.execute("SELECT id, hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
            n = self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        return {"count": n, "last_id": r["id"] if r else 0, "head_hash": r["hash"] if r else GENESIS}

    def verify(self):
        """Recompute the whole chain. Returns {ok, checked, broken_at, reason}."""
        prev, n = GENESIS, 0
        with self.lock: rows = self.db.execute("SELECT * FROM events ORDER BY id").fetchall()
        for r in rows:
            n += 1
            if r["prev_hash"] != prev: return {"ok": False, "checked": n, "broken_at": r["id"], "reason": "chain link missing (event removed or reordered)"}
            if sha256(prev + r["payload"]) != r["hash"]: return {"ok": False, "checked": n, "broken_at": r["id"], "reason": "event content was modified"}
            p = json.loads(r["payload"])
            if (p["ts"], p["source"], p["label"], p["severity"], p["score"]) != (r["ts"], r["source"], r["label"], r["severity"], r["score"]):
                return {"ok": False, "checked": n, "broken_at": r["id"], "reason": "event columns do not match signed content"}
            prev = r["hash"]
        return {"ok": True, "checked": n, "broken_at": None, "reason": "all links verified"}
