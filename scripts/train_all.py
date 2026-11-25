#!/usr/bin/env python3
"""Train all three detectors and write models/*.joblib + models/metrics.json.
Default = synthetic bootstrap data (no downloads). Real data flags:
  --phish-csv PhishTank.csv --benign-urls top-1m.csv --sms-tsv SMSSpamCollection --cicids-csv Friday-WorkingHours.csv
"""
import argparse, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix
from trinetra import data
from trinetra.phishing import PhishingDetector
from trinetra.sms import SMSDetector
from trinetra.network import NetworkDetector

ap = argparse.ArgumentParser()
ap.add_argument("--phish-csv"); ap.add_argument("--benign-urls"); ap.add_argument("--sms-tsv"); ap.add_argument("--cicids-csv"); ap.add_argument("--feedback-tsv", help="user corrections saved by Inbox Guard (data/feedback.tsv)")
ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models"))
a = ap.parse_args(); os.makedirs(a.out, exist_ok=True); M = {}


def prf(y, p, avg="binary"):
    pr, rc, f1, _ = precision_recall_fscore_support(y, p, average=avg, zero_division=0)
    return {"accuracy": round(accuracy_score(y, p), 4), "precision": round(pr, 4), "recall": round(rc, 4), "f1": round(f1, 4)}


# ---- phishing URLs
src = "real" if a.phish_csv else "synthetic"
U, y = data.load_url_feed(a.phish_csv, a.benign_urls) if a.phish_csv else data.gen_urls(6000)
Xtr, Xte, ytr, yte = train_test_split(U, y, test_size=.25, random_state=1, stratify=y)
m = PhishingDetector().fit(Xtr, ytr); p = [int(m.predict_proba(u) >= .5) for u in Xte]
m.save(f"{a.out}/phishing.joblib"); M["phishing_url"] = {"data": src, "n": len(U), **prf(yte, p)}

# ---- SMS
def choose_threshold(y, sc, max_fpr=0.01):
    """Pick the alert threshold on the VALIDATION set only: best F1 among thresholds whose false-alarm rate stays within budget."""
    best, best_f1 = 0.5, -1.0
    for th in np.linspace(0.2, 0.95, 76):
        p = sc >= th; tp = (p & (y == 1)).sum(); fp = (p & (y == 0)).sum(); fn = ((~p) & (y == 1)).sum()
        if fp / max((y == 0).sum(), 1) > max_fpr: continue
        f1 = 2 * tp / max(2 * tp + fp + fn, 1)
        if f1 >= best_f1: best, best_f1 = round(float(th), 2), f1
    return best


src = "real (UCI, de-duplicated) + synthetic India/Hinglish/Hindi augmentation (training only)" if a.sms_tsv else "synthetic"
if a.sms_tsv:
    T, y = data.load_uci_sms(a.sms_tsv); n_raw = len(T); T, y = data.dedupe(T, y)
    Rtr, Rrest, rytr, ryrest = train_test_split(T, y, test_size=.4, random_state=1, stratify=y)
    Rval, Rte, ryval, ryte = train_test_split(Rrest, ryrest, test_size=.5, random_state=2, stratify=ryrest)     # 60 / 20 / 20
    Ts, ys = data.gen_sms(1200)
    Ftx, fy = ([], np.array([], dtype=int))
    if a.feedback_tsv and os.path.exists(a.feedback_tsv): Ftx, fy = data.load_uci_sms(a.feedback_tsv); print(f"+ {len(Ftx)} user-feedback messages")
    s = SMSDetector().fit(Rtr + Ts + Ftx, np.concatenate([rytr, ys, fy]))
    sc_val = np.array([s.analyze(t, 0.5)["score"] for t in Rval]); sc_te = np.array([s.analyze(t, 0.5)["score"] for t in Rte])
    s.threshold = choose_threshold(ryval, sc_val)                      # chosen on validation; the test set is used once, for reporting
    pr_ = (sc_te >= s.threshold).astype(int); tab = []
    for th in (0.3, 0.4, 0.5, 0.6, 0.7, 0.85):
        p = (sc_te >= th).astype(int)
        tab.append({"threshold": th, **{k: v for k, v in prf(ryte, p).items() if k != "accuracy"},
                    "false_positives": int(((p == 1) & (ryte == 0)).sum()), "missed_scams": int(((p == 0) & (ryte == 1)).sum())})
    Tt, yt = data.gen_sms(600, seed=555)
    M["scam_sms"] = {"data": src, "split": {"train_real": len(Rtr), "validation": len(Rval), "test": len(Rte), "duplicates_removed": n_raw - len(T)},
                     "test_composition": {"legit": int((ryte == 0).sum()), "scam": int((ryte == 1).sum())},
                     "threshold": s.threshold, "threshold_chosen_on": "validation set (max 1% false positives)", **prf(ryte, pr_),
                     "false_positive_rate": round(float(((pr_ == 1) & (ryte == 0)).sum() / max((ryte == 0).sum(), 1)), 4),
                     "confusion_matrix": confusion_matrix(ryte, pr_).tolist(), "tradeoff_on_test": tab,
                     "india_synthetic_acc": round(accuracy_score(yt, [int(s.analyze(t)["score"] >= s.threshold) for t in Tt]), 4)}
else:
    T, y = data.gen_sms(4000)
    Xtr, Xte, ytr, yte = train_test_split(T, y, test_size=.25, random_state=1, stratify=y)
    s = SMSDetector().fit(Xtr, ytr); p = [int(s.analyze(t)["score"] >= .5) for t in Xte]
    M["scam_sms"] = {"data": src, "n": len(T), **prf(yte, p)}
s.save(f"{a.out}/sms.joblib")

# ---- network
src = "real" if a.cicids_csv else "synthetic"
X, y = data.load_cicids_csv(a.cicids_csv) if a.cicids_csv else data.gen_flows(8000)
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=.25, random_state=1, stratify=y)
n = NetworkDetector().fit(Xtr, ytr); p = n.rf.predict(Xte)
n.save(f"{a.out}/network.joblib")
M["network_flow"] = {"data": src, "n": len(X), **prf(yte, p, "macro"), "confusion_matrix": confusion_matrix(yte, p).tolist()}

M["note"] = ("Synthetic-data metrics measure pipeline correctness only and are NOT real-world accuracy. "
             "Re-run with --phish-csv/--sms-tsv/--cicids-csv for dataset results.")
import sklearn; open(f"{a.out}/sklearn_version.txt", "w").write(sklearn.__version__)
json.dump(M, open(f"{a.out}/metrics.json", "w"), indent=2); print(json.dumps(M, indent=2))
