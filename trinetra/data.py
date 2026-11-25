"""Data layer: synthetic generators (offline bootstrap) + loaders for real public datasets.

Synthetic data lets the project train/run with zero downloads (air-gapped friendly).
For real accuracy numbers, plug in PhishTank/OpenPhish, UCI SMS Spam, CICIDS/NSL-KDD
via the loaders below (see scripts/train_all.py flags).
"""
from __future__ import annotations
import csv, random, re
import numpy as np

# ----------------------------------------------------------------------------- URLs
BRANDS = ["sbi", "hdfcbank", "icicibank", "paytm", "phonepe", "amazon", "flipkart",
          "google", "microsoft", "apple", "netflix", "irctc", "incometax", "npci", "aadhaar"]
BENIGN_DOMAINS = ["wikipedia.org", "github.com", "python.org", "nic.in", "gov.in", "bbc.com",
    "thehindu.com", "ndtv.com", "stackoverflow.com", "arm.com", "iitb.ac.in", "swiggy.com",
    "zomato.com", "youtube.com", "linkedin.com", "medium.com", "nptel.ac.in", "isro.gov.in",
    "amazon.in", "flipkart.com", "sbi.co.in", "hdfcbank.com", "icicibank.com", "paytm.com",
    "irctc.co.in", "incometax.gov.in", "google.com", "microsoft.com", "apple.com", "netflix.com"]
BENIGN_SUBS = ["", "", "www.", "blog.", "docs.", "mail.", "m.", "accounts.", "netbanking.", "secure.", "login.", "support.", "pay.", "myaccount.", "retail.", "api."]
BENIGN_AUTH_PATHS = ["/login", "/signin", "/account/verify", "/secure/login.jsp", "/netbanking/", "/kyc/update", "/auth?client_id=abc123&redirect_uri=https%3A%2F%2Fapp", "/myaccount/settings", "/upi/pay", "/refund/status"]
BENIGN_PATHS = ["", "/", "/about", "/news/2024/story", "/docs/index.html", "/products/item-123",
    "/search?q=weather", "/wiki/Artificial_intelligence", "/courses/cs101", "/help/contact"]
BAD_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "icu", "buzz", "support", "work"]
BAD_WORDS = ["login", "verify", "secure", "update", "kyc", "account", "confirm", "banking",
             "wallet", "reward", "claim", "suspend", "refund", "upi", "otp", "signin"]


def _rand_str(rng, n):
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def gen_urls(n=4000, seed=7):
    rng = random.Random(seed)
    X, y = [], []
    for _ in range(n // 2):  # benign
        d = rng.choice(BENIGN_DOMAINS)
        sub = rng.choice(BENIGN_SUBS)
        path = rng.choice(BENIGN_AUTH_PATHS if rng.random() < .35 else BENIGN_PATHS)  # hard negatives: real login pages
        X.append(f"{rng.choice(['https','https','https','http'])}://{sub}{d}{path}")
        y.append(0)
    for _ in range(n // 2):  # phishing
        brand, word = rng.choice(BRANDS), rng.choice(BAD_WORDS)
        kind = rng.randint(0, 5)
        tld = rng.choice(BAD_TLDS)
        if kind == 0:   # brand as subdomain of junk domain
            u = f"http://{brand}.{word}-{_rand_str(rng,5)}.{tld}/{word}/index.php?id={_rand_str(rng,12)}"
        elif kind == 1:  # raw IP host
            u = f"http://{'.'.join(str(rng.randint(1,254)) for _ in range(4))}/{brand}/{word}.html"
        elif kind == 2:  # hyphenated lookalike
            u = f"https://{brand}-{word}-{rng.choice(['india','secure','care'])}.{tld}/{_rand_str(rng,8)}"
        elif kind == 3:  # @ trick
            u = f"http://{brand}.com@{_rand_str(rng,8)}.{tld}/{word}"
        elif kind == 4:  # typosquat + long path
            typo = brand.replace("a", "4").replace("o", "0").replace("i", "1")
            u = f"https://{typo}.com.{_rand_str(rng,4)}.{tld}/{word}/{_rand_str(rng,20)}?session={_rand_str(rng,16)}"
        else:            # punycode / deep subdomains
            u = f"http://xn--{_rand_str(rng,6)}.{brand}.{word}.{_rand_str(rng,5)}.{tld}/{word}"
        X.append(u); y.append(1)
    idx = list(range(len(X))); rng.shuffle(idx)
    return [X[i] for i in idx], np.array([y[i] for i in idx])


def load_url_feed(phish_csv, benign_txt=None, limit=50000):
    """PhishTank/OpenPhish export (csv with a 'url' column, or one URL per line) + benign list."""
    urls, labels = [], []
    with open(phish_csv, newline="", encoding="utf-8", errors="ignore") as f:
        head = f.readline(); f.seek(0)
        if "url" in head.lower():
            for r in csv.DictReader(f):
                u = r.get("url") or r.get("URL")
                if u: urls.append(u); labels.append(1)
        else:
            for line in f:
                if line.strip(): urls.append(line.strip()); labels.append(1)
    urls, labels = urls[:limit], labels[:limit]
    if benign_txt:
        with open(benign_txt, encoding="utf-8", errors="ignore") as f:
            for line in f.readlines()[:limit]:
                u = line.strip().split(",")[-1]
                if u: urls.append(u if "://" in u else "https://" + u); labels.append(0)
    return urls, np.array(labels)

# ----------------------------------------------------------------------------- SMS
SPAM_T = [
 "Dear customer your {bank} account will be blocked today. Update KYC now: {url}",
 "Congratulations! You won Rs {amt} in lucky draw. Claim reward at {url}",
 "URGENT: Your {bank} debit card is suspended. Call {ph} immediately to reactivate",
 "Your electricity will be disconnected tonight 9:30 PM. Pay pending bill: {url}",
 "Income Tax refund of Rs {amt} approved. Verify bank details: {url}",
 "Aapka {bank} account band ho jayega. Abhi KYC update karein {url}",
 "Aapne Rs {amt} jeeta hai! Inaam lene ke liye {url} par click karein",
 "Work from home, earn Rs {amt} daily. Join Telegram group now {url}",
 "Your parcel is held at customs. Pay Rs {amt} redelivery fee: {url}",
 "FREE entry! Win a new iPhone. Text WIN to {ph}. T&C apply",
 "Your UPI PIN expires today. Share OTP to avoid account freeze {url}",
 "Loan approved Rs {amt} without documents! Apply instantly {url}",
 "Aapka SIM 24 ghante mein block hoga. Verify karne ke liye {ph} par call karein",
 "Dear user, unusual login detected on your {bank} netbanking. Secure account: {url}",
 "Lottery winner! Send Aadhaar and bank details to claim Rs {amt} prize",
]
HAM_T = [
 "Hi, are we still meeting for lunch at 1pm tomorrow?", "Your OTP for login is {otp}. Do not share it with anyone. -{bank}",
 "Mom called, please ring her back when free", "Rs {amt} debited from a/c XX{otp} on 12-Jan. Avl bal updated. -{bank}",
 "Your order has been shipped and will arrive by Friday", "Meeting moved to 4pm. Conference room B.",
 "Happy birthday! Have a great year ahead", "Bhai kal cricket khelne chalna hai kya?",
 "Reminder: your appointment with Dr. Shah is on Monday 10am", "Can you send me the notes from today's class?",
 "Your electricity bill of Rs {amt} is generated. Pay via official app before due date.",
 "Dinner ready, come home soon", "Train 12951 is on time. Platform 3.", "Aaj office late tak rukna padega, dinner mat banana",
 "Thanks for the payment. Receipt attached in your email.",
]


def _fill(t, rng):
    return t.format(bank=rng.choice(["SBI", "HDFC", "ICICI", "Axis", "PNB"]),
        url=rng.choice(["http://bit.ly/", "http://tinyurl.com/", "https://sbi-kyc." + rng.choice(BAD_TLDS) + "/"]) + _rand_str(rng, 6),
        amt=rng.choice(["5,000", "25,000", "1,00,000", "49,999", "8,500", "350"]),
        ph="".join(rng.choice("0123456789") for _ in range(10)), otp="".join(rng.choice("0123456789") for _ in range(6)))


def gen_sms(n=3000, seed=11):
    rng = random.Random(seed); X, y = [], []
    for _ in range(n // 2):
        X.append(_fill(rng.choice(SPAM_T), rng)); y.append(1)
        X.append(_fill(rng.choice(HAM_T), rng)); y.append(0)
    idx = list(range(len(X))); rng.shuffle(idx)
    return [X[i] for i in idx], np.array([y[i] for i in idx])


def load_uci_sms(path):
    """UCI SMS Spam Collection: tab-separated 'ham|spam<TAB>text'."""
    X, y = [], []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "\t" in line:
                lab, txt = line.rstrip("\n").split("\t", 1)
                X.append(txt); y.append(1 if lab.strip().lower() == "spam" else 0)
    return X, np.array(y)

# ----------------------------------------------------------------------------- Network flows
FLOW_FEATURES = ["duration", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "pkt_len_mean",
                 "pkt_len_std", "bytes_per_s", "pkts_per_s", "syn_cnt", "rst_cnt", "ack_cnt",
                 "iat_mean", "iat_std", "dst_port"]
FLOW_CLASSES = ["benign", "port_scan", "dos_flood", "brute_force", "botnet_c2"]


def gen_flows(n=6000, seed=3):
    rng = np.random.default_rng(seed); rows, labels = [], []
    for _ in range(n):
        c = rng.choice(5, p=[0.55, 0.12, 0.12, 0.11, 0.10])
        rows.append(make_flow(FLOW_CLASSES[c], rng)); labels.append(c)
    return np.array(rows, dtype=float), np.array(labels)


def make_flow(kind, rng=None):
    """Return one synthetic flow feature vector of the given class."""
    rng = rng or np.random.default_rng()
    if kind == "benign":
        fp, bp = rng.integers(3, 80), rng.integers(3, 120); dur = rng.exponential(4) + .05
        fb, bb = fp * float(np.clip(rng.normal(300, 120), 40, 1400)), bp * float(np.clip(rng.normal(700, 300), 40, 1500))
        syn, rst, ack = 1, rng.integers(0, 2), fp + bp - 2; iat = dur / (fp + bp); iats = iat * rng.uniform(.5, 2)
        port = rng.choice([80, 443, 443, 53, 8080, 993, 22, 123])
    elif kind == "port_scan":
        fp, bp = rng.integers(1, 3), rng.integers(0, 2); dur = rng.uniform(.0005, .05)
        fb, bb = fp * 44, bp * 40; syn, rst, ack = fp, bp, 0; iat = dur / 2; iats = iat * .1
        port = int(rng.integers(1, 65535))
    elif kind == "dos_flood":
        fp, bp = rng.integers(2000, 20000), rng.integers(0, 20); dur = rng.uniform(1, 10)
        fb, bb = fp * rng.uniform(40, 100), bp * 40; syn, rst, ack = fp, rng.integers(0, 10), bp
        iat = dur / fp; iats = iat * .2; port = rng.choice([80, 443, 53])
    elif kind == "brute_force":
        fp, bp = rng.integers(8, 20), rng.integers(8, 20); dur = rng.uniform(.3, 2)
        fb, bb = fp * rng.uniform(60, 130), bp * rng.uniform(60, 130); syn, rst, ack = 1, rng.integers(0, 3), fp + bp - 2
        iat = dur / (fp + bp); iats = iat * .3; port = rng.choice([22, 21, 3389, 23])
    else:  # botnet_c2: periodic small packets, long-lived
        fp, bp = rng.integers(10, 40), rng.integers(10, 40); dur = rng.uniform(60, 600)
        fb, bb = fp * rng.uniform(80, 200), bp * rng.uniform(80, 400); syn, rst, ack = 1, 0, fp + bp - 2
        iat = dur / (fp + bp); iats = iat * .02; port = rng.choice([443, 8443, 4444, 6667, 1337])
    tot = max(fp + bp, 1); plm = (fb + bb) / tot; pls = plm * rng.uniform(.1, .6)
    return [float(v) for v in (dur, fp, bp, fb, bb, plm, pls, (fb + bb) / max(dur, 1e-6), tot / max(dur, 1e-6),
                               syn, rst, ack, iat, iats, port)]


def load_cicids_csv(path, limit=200000):
    """Best-effort mapper for CICIDS2017 'MachineLearningCSV' style files -> our FLOW_FEATURES."""
    col_map = {"duration": "Flow Duration", "fwd_pkts": "Total Fwd Packets", "bwd_pkts": "Total Backward Packets",
        "fwd_bytes": "Total Length of Fwd Packets", "bwd_bytes": "Total Length of Bwd Packets",
        "pkt_len_mean": "Packet Length Mean", "pkt_len_std": "Packet Length Std", "bytes_per_s": "Flow Bytes/s",
        "pkts_per_s": "Flow Packets/s", "syn_cnt": "SYN Flag Count", "rst_cnt": "RST Flag Count",
        "ack_cnt": "ACK Flag Count", "iat_mean": "Flow IAT Mean", "iat_std": "Flow IAT Std",
        "dst_port": "Destination Port"}

    def label_map(s):
        u = s.upper().replace(" ", "")
        if u == "BENIGN": return 0
        if "PORTSCAN" in u: return 1
        if "DOS" in u or "DDOS" in u: return 2
        if "PATATOR" in u or "BRUTE" in u: return 3
        return 4  # bot / infiltration / others -> c2 bucket

    X, y = [], []
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        rd = csv.DictReader(f); rd.fieldnames = [h.strip() for h in rd.fieldnames]
        for i, r in enumerate(rd):
            if i >= limit: break
            try:
                row = [float(r[col_map[k]]) for k in FLOW_FEATURES]
                row[0] /= 1e6; row[12] /= 1e6; row[13] /= 1e6  # microseconds -> seconds
                if not np.all(np.isfinite(row)): continue
                X.append(row); y.append(label_map(r["Label"].strip()))
            except (KeyError, ValueError):
                continue
    return np.array(X), np.array(y)


# Realistic LEGIT messages that contain scary words (bank, OTP, KYC, UPI) - so the model cannot learn "KYC/OTP/bank = scam".
HAM_T += [
 "Rs {amt} credited to your a/c XX{otp} via UPI. Avl bal Rs 12,450. -{bank}",
 "UPI: Rs {amt} paid to Swiggy. Ref {otp}. If not you, call the number on your card. -{bank}",
 "Your OTP is {otp} for a UPI transaction of Rs {amt}. Do not share it with anyone. -{bank}",
 "Reminder: please complete your KYC by visiting your nearest {bank} branch with original documents. No link or OTP is needed.",
 "Your KYC update request has been received. Status will be sent to your registered email. -{bank}",
 "Dear customer, your {bank} credit card statement of Rs {amt} is generated. Pay via the official app.",
 "Your Amazon package will be delivered today by 8 PM. Track it in the Amazon app.",
 "Aapka parcel aaj shaam tak deliver ho jayega. Koi payment ya OTP dene ki zaroorat nahi hai.",
 "आपका OTP {otp} है। इसे किसी के साथ साझा न करें। -{bank}",
 "आपके खाते में Rs {amt} जमा हुए। -{bank}",
 "Your electricity bill of Rs {amt} is due on 20th. Pay only via the official app or website.",
 "Mutual fund SIP of Rs {amt} was processed successfully. -{bank}",
]
SPAM_T += [
 "आपका {bank} खाता आज बंद हो जाएगा। अभी KYC अपडेट करें {url}",
 "बधाई हो! आपने Rs {amt} का इनाम जीता है। लेने के लिए {url} पर क्लिक करें",
 "Your {bank} KYC has expired. Account will be frozen in 24 hours. Update at {url}",
 "SBI YONO: Rs {amt} reward points expire today. Redeem now {url}",
]


def dedupe(texts, labels):
    """Drop exact and near-duplicate messages (case/space/digit-insensitive) BEFORE splitting, so copies cannot leak into the test set."""
    seen, X, y = set(), [], []
    for t, l in zip(texts, labels):
        k = re.sub(r"\d+", "0", re.sub(r"\s+", " ", t.lower().strip()))
        if k in seen: continue
        seen.add(k); X.append(t); y.append(l)
    return X, np.array(y)
