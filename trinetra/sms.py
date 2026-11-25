"""Scam/spam SMS detector: word+char TF-IDF -> Logistic Regression, blended with explainable
rule signals (urgency, credential requests, links, Hinglish scam phrases). Offline, ~100 KB."""
from __future__ import annotations
import re, joblib
import numpy as np
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

URL_RE = re.compile(r"(https?://\S+|www\.\S+|\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly)/\S+)", re.I)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[- ]?)?[6-9]\d{9}(?!\d)")
RULES = [  # (name, regex, human explanation)
    ("urgency", r"\b(urgent|immediately|today|tonight|within \d+ ?(hours|hrs)|expires?|last chance|abhi|turant|24 ghante)\b",
     "creates false urgency to rush you"),
    ("credentials", r"\b(otp|pin|cvv|password|aadhaar|aadhar|pan|card number|bank details|share)\b.{0,40}\b(otp|pin|cvv|aadhaar|details|share|verify|update)\b|\b(share|send|verify|update).{0,25}\b(otp|pin|cvv|aadhaar|kyc|bank details)\b",
     "asks for sensitive info (OTP/PIN/Aadhaar/bank details)"),
    ("kyc_block", r"\b(kyc|account.{0,25}(block|suspend|freeze|band)|sim.{0,20}block|card.{0,20}suspend|disconnect)",
     "threatens account/SIM/service blocking (classic KYC scam)"),
    ("prize", r"\b(won|winner|lottery|lucky draw|jeeta|inaam|prize|reward|congratulations|free entry|iphone)\b",
     "promises a prize or reward you never applied for"),
    ("money_lure", r"\b(refund|loan approved|earn rs|work from home|daily income|redelivery fee|customs)\b",
     "offers easy money or demands a small 'fee'"),
]


NEG_RE = re.compile(r"\b(do not|don't|dont|never|not|nahi|mat)\s+(to\s+)?(share|give|tell|disclose|batao|bataye)\b[^.!?\n]*", re.I)


def rule_signals(text: str):
    clean = NEG_RE.sub(" ", text)  # "Do not share your OTP" is a safety warning, not a credential request
    hits = [(n, why) for n, rx, why in RULES if re.search(rx, clean, re.I)]
    urls = URL_RE.findall(text); ph = PHONE_RE.findall(text)
    if urls: hits.append(("link", "contains a link (never tap links in unexpected messages)"))
    if ph and any(n in ("urgency", "kyc_block", "prize") for n, _ in hits):
        hits.append(("callback", "asks you to call an unknown number"))
    return hits, urls


class SMSDetector:
    def __init__(self):
        self.wv = TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, lowercase=True)
        self.cv = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), min_df=3, sublinear_tf=True, max_features=15000)
        self.clf = LogisticRegression(C=4.0, max_iter=400, class_weight="balanced")

    @staticmethod
    def _norm(t):  # normalise numbers/urls so the model learns patterns, not specific values
        t = URL_RE.sub(" URLTOKEN ", t); t = PHONE_RE.sub(" PHONETOKEN ", t)
        return re.sub(r"\d+", "0", t)

    def fit(self, texts, y):
        T = [self._norm(t) for t in texts]
        X = hstack([self.wv.fit_transform(T), self.cv.fit_transform(T)]).tocsr()
        self.clf.fit(X, y); self._nw = len(self.wv.vocabulary_); return self

    def _vec(self, text):
        T = [self._norm(text)]
        return hstack([self.wv.transform(T), self.cv.transform(T)]).tocsr()

    def predict_proba(self, text):
        return float(self.clf.predict_proba(self._vec(text))[0, 1])

    def top_terms(self, text, k=4):
        X = self._vec(text); contrib = X.multiply(self.clf.coef_[0]).tocsr()
        inv = {i: w for w, i in self.wv.vocabulary_.items()}
        items = [(inv[j], v) for j, v in zip(contrib.indices, contrib.data) if j < self._nw and v > 0]
        return [w for w, _ in sorted(items, key=lambda t: -t[1])[:k]]

    def analyze(self, text, threshold=None):
        threshold = getattr(self, "threshold", 0.5) if threshold is None else threshold   # set from the VALIDATION split in train_all.py
        ml = self.predict_proba(text); hits, urls = rule_signals(text)
        strong = sum(1 for n, _ in hits if n in ("urgency", "credentials", "kyc_block", "prize", "money_lure", "callback"))
        score = float(min(1.0, 0.8 * ml + 0.2 * min(strong / 2, 1.0)))
        return {"type": "scam_sms", "input": text, "score": round(score, 4), "ml_score": round(ml, 4),
                "label": "scam" if score >= threshold else "safe",
                "evidence": [w for _, w in hits], "urls": urls, "top_terms": self.top_terms(text)}

    def save(self, path): joblib.dump(self, path, compress=3)

    @staticmethod
    def load(path): return joblib.load(path)
