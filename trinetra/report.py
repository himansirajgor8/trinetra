"""Builds the forensic / incident-activity PDF for any time range from the tamper-evident event log."""
from __future__ import annotations
import calendar, platform, re, textwrap, time
from collections import Counter
from .pdfwriter import PDF, W, H
from .forensics import sha256, GENESIS

NAVY, GREY, DARK = (0.07, 0.15, 0.3), (0.42, 0.45, 0.5), (0.12, 0.13, 0.16)
SEV = {"high": (0.78, 0.1, 0.1), "medium": (0.8, 0.42, 0.0), "low": (0.62, 0.5, 0.0), "none": (0.1, 0.5, 0.2)}
SRC = {"url": "URL CHECK", "sms": "SMS CHECK", "network": "NETWORK", "inbox": "INBOX", "user_action": "USER ACTION"}
ORIGIN = {"simulated": "[SIMULATED DEMO DATA]", "manual": "[MANUAL TEST ENTRY]", "live": "[LIVE]", "api": "[API]"}
MAX_ITEMS = 1500


def fmt(ts): return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
def clean(s): return " ".join(str(s).split())


class Doc:
    M, BOT = 40, 58

    def __init__(self, title):
        self.p = PDF(title); self.new()

    def new(self): self.p.new_page(); self.y = H - 50

    def need(self, h):
        if self.y - h < self.BOT: self.new()

    def h1(self, s):
        self.need(80); self.y -= 8; self.p.text(self.M, self.y - 12, s, "F2", 13, NAVY); self.y -= 18
        self.p.line(self.M, self.y, W - self.M, self.y, NAVY, 0.8); self.y -= 8

    def line(self, s, font="F3", size=8.5, color=DARK, indent=0):
        self.need(size * 1.4); self.p.text(self.M + indent, self.y - size, s, font, size, color); self.y -= size * 1.4

    def wrap(self, s, size=8.5, indent=0, labw=0):
        return textwrap.wrap(clean(s), int((W - 2 * self.M - indent) / (0.6 * size)) - labw, break_long_words=True, break_on_hyphens=False) or [""]

    def kv(self, label, value, size=8.5, indent=0, labw=9, color=DARK):
        ls = self.wrap(value, size, indent, labw)
        for i, l in enumerate(ls): self.line((label.ljust(labw) if i == 0 else " " * labw) + l, "F3", size, color, indent)

    def para(self, s, size=8.5, indent=0, color=DARK, bullet=""):
        ls = self.wrap(s, size, indent, len(bullet))
        for i, l in enumerate(ls): self.line((bullet if i == 0 else " " * len(bullet)) + l, "F3", size, color, indent)

    def gap(self, h=6): self.y -= h

    def finish(self, footer):
        n = self.p.page_count()
        for i, pg in enumerate(self.p.pages, 1):
            self.p.cur = pg
            self.p.line(self.M, 42, W - self.M, 42, (0.8, 0.8, 0.8), 0.5)
            self.p.text(self.M, 30, footer, "F3", 7, GREY); self.p.text(W - self.M - 60, 30, f"Page {i} of {n}", "F3", 7, GREY)
        return self.p.output()


def build_report(log, info, start, end, include_safe=False, redact=False, case="", detail_limit=MAX_ITEMS):
    gen = time.time()
    events = log.query(start, end, include_safe=True)
    threats = [e for e in events if e["severity"] != "none"]
    safe = [e for e in events if e["severity"] == "none" and e["source"] != "user_action"]
    actions = [e for e in events if e["source"] == "user_action"]
    chain = log.verify(); head = log.head()
    digest = sha256("".join(e["hash"] for e in events)) if events else sha256("")
    rid = sha256(f"{start}|{end}|{digest}|{gen}")[:12].upper()
    shown = lambda t: f"[redacted | sha256:{sha256(t)[:16]} | {len(t)} chars]" if redact else t
    origins = Counter(e["detail"].get("origin", "api") for e in events)
    tz = time.strftime("%Z (UTC%z)")

    d = Doc("Trinetra Forensic Activity Report")
    d.p.rect(0, H - 92, W, 92, NAVY)
    d.p.text(d.M, H - 44, "Trinetra", "F2", 22, (1, 1, 1))
    d.p.text(d.M, H - 66, "Forensic Activity Report  |  On-device AI security assistant", "F1", 11, (0.8, 0.88, 1))
    d.p.text(d.M, H - 82, f"Report ID {rid}", "F3", 8, (0.8, 0.88, 1)); d.y = H - 110

    d.h1("1. Report details")
    for k, v in [("Case ref", case or "(not provided)"), ("Generated", f"{fmt(gen)}  {tz}"), ("Period", (f"{fmt(start)}  ->  {fmt(end)}" if start > 86400 else f"beginning of log  ->  {fmt(end)}")),
                 ("Device", info.get("host", "?")), ("OS", info.get("os", "?")), ("Software", f"Trinetra {info.get('version', '')}, Python {info.get('python', '')}"),
                 ("Advisor", info.get("advisor", "?")), ("Filters", f"safe events {'included' if include_safe else 'summarised only'}; message content {'REDACTED' if redact else 'shown in full'}")]:
        d.kv(k, v, labw=10)
    if origins.get("simulated") or origins.get("manual"):
        d.gap(); d.para(f"NOTE: this period contains {origins.get('simulated', 0)} SIMULATED demo event(s) and {origins.get('manual', 0)} MANUAL test entr(y/ies). "
                        "They are labelled in the listing and are NOT evidence of a real incident.", 8.5, color=SEV["medium"])

    d.h1("2. Log integrity (tamper-evidence)")
    ok = chain["ok"]
    d.line(("VERIFIED - hash chain intact (%d events checked)" % chain["checked"]) if ok else
           f"WARNING - CHAIN BROKEN at event #{chain['broken_at']}: {chain['reason']}", "F4", 9.5, SEV["none"] if ok else SEV["high"])
    d.gap(3)
    d.kv("Events", f"{len(events)} in this period / {head['count']} in full log", labw=15)
    d.kv("Chain head", head["head_hash"], labw=15)
    d.kv("Period digest", digest, labw=15)
    d.kv("First link", events[0]["prev_hash"] if events else GENESIS, labw=15)
    d.gap(3)
    d.para("Each event's hash covers its content and the previous event's hash, so editing or removing an earlier event breaks the chain from that point. "
           "This detects accidental or casual tampering; it cannot stop someone with full write access from rebuilding the whole log. "
           "Record the Chain head and Period digest outside this device (case file, e-mail, printout) to anchor the report.", 8)

    d.h1("3. Executive summary")
    if not events:
        d.para("No events were recorded in the selected period.")
    else:
        d.para(f"{len(events)} events were recorded; {len(threats)} were flagged as threats (high {sum(e['severity']=='high' for e in threats)}, "
               f"medium {sum(e['severity']=='medium' for e in threats)}, low {sum(e['severity']=='low' for e in threats)}); {len(safe)} were judged safe; "
               f"{len(actions)} were user actions on the system.")
        d.gap(4); d.line("Source".ljust(14) + "Total".rjust(7) + "High".rjust(7) + "Medium".rjust(8) + "Low".rjust(6) + "Safe".rjust(7), "F4", 8.5, NAVY)
        for s in ("url", "sms", "network", "inbox", "user_action"):
            es = [e for e in events if e["source"] == s]
            if es:
                cols = ["0", "0", "0", "-"] if s == "user_action" else [str(sum(e["severity"] == v for e in es)) for v in ("high", "medium", "low", "none")]
                d.line(SRC[s].ljust(14) + str(len(es)).rjust(7) + "".join(x.rjust(w) for x, w in zip(cols, (7, 8, 6, 7))))
        d.gap(6)
        labels = Counter(e["label"] for e in threats)
        if labels: d.kv("Top threats", ", ".join(f"{k} x{v}" for k, v in labels.most_common(6)), labw=13)
        off = Counter()
        for e in threats:
            dt = e["detail"]; who = dt.get("src") or dt.get("sender")
            if who and e["source"] in ("network", "inbox"): off[who] += 1
        if off: d.kv("Top sources", ", ".join(f"{k} ({v})" for k, v in off.most_common(6)), labw=13)
        # timeline
        span = (events[-1]["ts"] - events[0]["ts"]) if events else 0; step = 3600 if span <= 172800 else 86400
        loc = lambda t: calendar.timegm(time.localtime(t)) - int(t)      # local-time offset (India is UTC+5:30, so buckets must follow LOCAL hours)
        b = Counter(int((e["ts"] + loc(e["ts"])) // step) for e in threats)
        if b:
            d.gap(4); d.line("Threat timeline (%s buckets)" % ("hourly" if step == 3600 else "daily"), "F4", 8.5, NAVY)
            top = max(b.values()); keys = sorted(b)
            for k in keys[:60]: d.line(time.strftime("%m-%d %H:00" if step == 3600 else "%Y-%m-%d", time.gmtime(k * step)).ljust(12) + ("#" * max(1, round(36 * b[k] / top))).ljust(38) + str(b[k]), "F3", 8)
            if len(keys) > 60: d.line(f"... {len(keys) - 60} more buckets not shown", "F3", 8, GREY)

    def render(e):
        dt, s = e["detail"], e["source"]; txt = dt.get("input") or dt.get("text") or ""
        d.need((9 + min(len(dt.get("evidence", [])), 8) + len(d.wrap(txt, 8.5, 8, 9)) + (1 if dt.get("urls") else 0)) * 12.5)   # keep one finding on one page
        tag = ORIGIN.get(dt.get("origin", "api"), "")
        title = f"#{e['id']}  {fmt(e['ts'])}  {e['severity'].upper():<6} {SRC.get(s, s)}: {e['label']}"
        d.line(title, "F4", 8.8, SEV.get(e["severity"], DARK)); ind = 8
        if tag: d.line(tag, "F3", 7.5, GREY, ind)
        if s == "url": d.kv("URL", shown(dt.get("input", "")), indent=ind, labw=9)
        elif s == "sms": d.kv("Message", shown(dt.get("input", "")), indent=ind, labw=9)
        elif s == "network": d.kv("Flow", f"{dt.get('src')} -> {dt.get('dst')}:{dt.get('dport')}", indent=ind, labw=9)
        elif s == "inbox":
            d.kv("From", f"{dt.get('sender')} ({dt.get('channel')})", indent=ind, labw=9)
            d.kv("Action", f"{dt.get('action', '').upper()} by policy (block >= {dt.get('block_threshold')}, warn >= {dt.get('warn_threshold')})" + (" - trusted sender" if dt.get("trusted") else ""), indent=ind, labw=9)
            d.kv("Message", shown(dt.get("text", "")), indent=ind, labw=9)
        elif s == "user_action" and dt.get("action") == "report_generated":
            d.kv("Action", f"report {dt.get('report_id')} generated for {fmt(dt.get('from', 0))} -> {fmt(dt.get('to', 0))}", indent=ind, labw=9)
        elif s == "user_action":
            d.kv("Action", f"{dt.get('action')} message #{dt.get('message_id')} from {dt.get('sender')}" + (" (sender now trusted)" if dt.get("trust_sender") else ""), indent=ind, labw=9)
            if dt.get("text"): d.kv("Message", shown(dt["text"]), indent=ind, labw=9)
        if s != "user_action": d.kv("Score", f"{e['score']}" + (f"  confidence {dt['confidence']}" if "confidence" in dt else ""), indent=ind, labw=9)
        for w in dt.get("evidence", [])[:8]: d.para(re.sub(r"(https?://|www\.)\S+", "[link redacted]", w) if redact else w, 8.3, ind + 6, bullet="- ")
        if dt.get("urls"): d.kv("Links", ", ".join(shown(u) for u in dt["urls"][:4]), indent=ind, labw=9)
        if txt: d.kv("SHA-256", sha256(txt), size=7.5, indent=ind, labw=9, color=GREY)
        d.kv("Event hash", e["hash"], size=7.5, indent=ind, labw=11, color=GREY); d.gap(5)

    if threats: d.need(270)   # heading + note + first finding together
    d.h1(f"4. Threat findings ({len(threats)})")
    if not include_safe and safe: d.para(f"Numbers (#) are log IDs. {len(safe)} event(s) judged safe are not listed, so some numbers are skipped; tick 'include safe events' to list them.", 8, color=GREY)
    if not threats: d.para("No threats were flagged in this period.")
    for e in threats[:detail_limit]: render(e)
    if len(threats) > detail_limit: d.para(f"... {len(threats) - detail_limit} further findings omitted. Narrow the time range to list them.", color=SEV["medium"])

    d.h1(f"5. User actions ({len(actions)})")
    if not actions: d.para("No restore / confirm / delete actions were taken.")
    for e in actions[:detail_limit]: render(e)

    if include_safe:
        d.h1(f"6. Events judged safe ({len(safe)})")
        for e in safe[:detail_limit]: render(e)
        if len(safe) > detail_limit: d.para(f"... {len(safe) - detail_limit} further safe events omitted.", color=GREY)

    d.h1("Recommended next steps")
    acts = []
    for e in threats:
        for a in e["detail"].get("actions", []):
            if a not in acts: acts.append(a)
    for a in acts[:8]: d.para(a, 8.5, 4, bullet="- ")
    for a in ["Do not wipe or reset a compromised device before evidence is copied; note the time you noticed the problem.",
              "Copy data/forensic_log.db and this PDF to separate media, and record the Chain head hash elsewhere.",
              "Change passwords from a different, clean device and enable two-factor authentication.",
              "Report cyber-fraud at cybercrime.gov.in or call 1930 (India); inform your bank at once for financial fraud."]:
        d.para(a, 8.5, 4, bullet="- ")

    d.h1("Limitations")
    for a in ["Detections are automated and probabilistic. A flag is an indicator for investigation, not proof of wrongdoing.",
              "The log shows only what Trinetra observed or was given; it is not a full forensic image of a device.",
              "Events labelled SIMULATED or MANUAL come from the demo simulator or hand-typed tests, not from real traffic.",
              "Text outside Latin-1 (e.g. Devanagari) prints as '?' in this PDF; the SHA-256 shown with each message identifies the original stored text.",
              "Times are shown in the device's local time zone; confirm the device clock was correct."]:
        d.para(a, 8.3, 4, bullet="- ")

    pdf = d.finish(f"Trinetra forensic report | ID {rid} | digest {digest[:16]}")
    return pdf, {"report_id": rid, "events": len(events), "threats": len(threats), "chain_ok": ok, "digest": digest}


def device_info(advisor_mode="template"):
    from . import __version__
    return {"host": platform.node() or "unknown", "os": platform.platform(), "python": platform.python_version(), "version": __version__, "advisor": advisor_mode}
