"""Phishing URL detector: lexical + brand-impersonation features -> small Random Forest.
Fully offline: no DNS, no WHOIS, no page fetch (so it is private and works air-gapped)."""
from __future__ import annotations
import math, re, joblib
from urllib.parse import urlparse
import numpy as np
from sklearn.ensemble import RandomForestClassifier

OFFICIAL = {  # brand token -> legitimate registered domains
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"}, "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"}, "paytm": {"paytm.com"}, "phonepe": {"phonepe.com"},
    "amazon": {"amazon.in", "amazon.com"}, "flipkart": {"flipkart.com"}, "google": {"google.com"},
    "microsoft": {"microsoft.com"}, "apple": {"apple.com"}, "netflix": {"netflix.com"},
    "irctc": {"irctc.co.in"}, "incometax": {"incometax.gov.in"}, "npci": {"npci.org.in"},
    "aadhaar": {"uidai.gov.in"},
}
SUSP_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "icu", "buzz", "support", "work", "zip", "mov"}
KEYWORDS = ["login", "verify", "secure", "update", "kyc", "account", "confirm", "banking",
            "wallet", "reward", "claim", "suspend", "refund", "upi", "otp", "signin"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"}
FEATURES = ["url_len", "host_len", "n_dots", "n_hyphens", "n_digits_ratio", "has_ip", "has_at", "is_https",
            "subdomain_depth", "entropy", "kw_count", "susp_tld", "brand_mismatch", "punycode",
            "path_len", "query_len", "n_special", "shortener", "port_nonstd"]
_ip = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _entropy(s):
    if not s: return 0.0
    p = [s.count(c) / len(s) for c in set(s)]
    return -sum(x * math.log2(x) for x in p)


def parse(url: str):
    u = url.strip()
    if "://" not in u: u = "http://" + u
    pu = urlparse(u)
    host = (pu.hostname or "").lower()
    parts = host.split(".")
    # naive registered-domain: handle common 2-level public suffixes used in India
    two = {"co.in", "gov.in", "ac.in", "org.in", "net.in", "com.au", "co.uk"}
    reg = ".".join(parts[-3:]) if len(parts) >= 3 and ".".join(parts[-2:]) in two else ".".join(parts[-2:])
    return u, pu, host, parts, reg


def features(url: str):
    u, pu, host, parts, reg = parse(url)
    tld = parts[-1] if parts else ""
    full = u.lower()
    brand_mismatch = 0
    for b, legit in OFFICIAL.items():
        if b in host and reg not in legit:
            brand_mismatch = 1; break
    if "@" in pu.netloc: brand_mismatch = max(brand_mismatch, int(any(b in pu.netloc.split("@")[0] for b in OFFICIAL)))
    return [len(u), len(host), host.count("."), host.count("-"), sum(c.isdigit() for c in host) / max(len(host), 1),
            int(bool(_ip.match(host))), int("@" in pu.netloc), int(pu.scheme == "https"),
            max(len(parts) - 2, 0), _entropy(host), sum(k in full for k in KEYWORDS), int(tld in SUSP_TLDS),
            brand_mismatch, int("xn--" in host), len(pu.path), len(pu.query),
            sum(not c.isalnum() for c in full), int(reg in SHORTENERS), int(pu.port not in (None, 80, 443))]


def reasons(url: str):
    """Human-readable evidence derived from features (independent of the ML score)."""
    f = dict(zip(FEATURES, features(url))); r = []
    if f["has_ip"]: r.append("uses a raw IP address instead of a domain name")
    if f["has_at"]: r.append("contains '@' which can hide the real destination")
    if f["brand_mismatch"]: r.append("mentions a well-known brand but is NOT that brand's official domain")
    if f["susp_tld"]: r.append("uses a top-level domain commonly abused by scammers")
    if f["kw_count"] >= 2: r.append("contains several urgency/credential words (login, verify, kyc...)")
    if f["punycode"]: r.append("uses punycode (xn--), often used for look-alike characters")
    if f["subdomain_depth"] >= 3: r.append("has an unusually deep chain of subdomains")
    if f["shortener"]: r.append("is a shortened link that hides the real destination")
    if not f["is_https"]: r.append("is not using HTTPS")
    if f["n_hyphens"] >= 3: r.append("has many hyphens in the domain name")
    return r


class PhishingDetector:
    def __init__(self, model=None):
        self.model = model

    def fit(self, urls, y, seed=0):
        X = np.array([features(u) for u in urls])
        self.model = RandomForestClassifier(n_estimators=60, max_depth=12, n_jobs=-1, random_state=seed).fit(X, y)
        return self

    def predict_proba(self, url: str) -> float:
        return float(self.model.predict_proba(np.array([features(url)]))[0, 1])

    def analyze(self, url: str, threshold=0.5):
        p = self.predict_proba(url); rs = reasons(url)
        _, pu, host, parts, reg = parse(url)
        if any(reg in legit for legit in OFFICIAL.values()) and not _ip.match(host) and "@" not in pu.netloc:
            p *= 0.25; rs = ["matches the official domain of a known brand"]  # allowlist damping
        return {"type": "phishing_url", "input": url, "score": round(p, 4),
                "label": "malicious" if p >= threshold else "safe", "evidence": rs}

    def save(self, path): joblib.dump(self.model, path, compress=3)

    @classmethod
    def load(cls, path):
        m = joblib.load(path); m.n_jobs = 1  # avoid thread-pool overhead on single-sample inference (edge devices)
        return cls(m)
