"""Advisory / reasoning layer.

PIPELINE A (this module):  Llama (Llama 3.2 1B/3B Instruct) running through **ExecuTorch** on the Arm CPU.
PIPELINE B (optional):     Hailo NPU via HailoRT for vision-style workloads - a SEPARATE pipeline, documented
                           in docs/HAILO.md. Llama never runs on the Hailo NPU.

Safety design: classical detectors decide the VERDICT; Llama only writes the plain-language EXPLANATION.
Remediation steps come from a curated playbook, so an LLM hallucination can never produce a harmful
instruction or flip a verdict. If the Llama runtime/model is missing, a deterministic template engine
answers instead and the response says so (source = "template").
"""
from __future__ import annotations
import json, os, shutil, subprocess, textwrap

PLAYBOOK = {
 "phishing_url": {
  "en": ["Do not open the link or enter any password, OTP or card details.", "If you already entered details, change that password now and call your bank's official number.",
         "Report it: forward to the real brand's support or to cybercrime.gov.in / call 1930 (India).", "Delete the message that contained the link."],
  "hi": ["लिंक न खोलें और कोई पासवर्ड, OTP या कार्ड की जानकारी न डालें।", "अगर जानकारी डाल चुके हैं तो तुरंत पासवर्ड बदलें और बैंक के आधिकारिक नंबर पर कॉल करें।",
         "cybercrime.gov.in पर रिपोर्ट करें या 1930 पर कॉल करें।", "वह मैसेज डिलीट कर दें।"]},
 "scam_sms": {
  "en": ["Do not reply, tap links, or call the number in the message.", "Never share OTP, PIN, CVV or Aadhaar with anyone - banks never ask for them.",
         "Verify only via the official app or the number printed on your card.", "Report the sender via 1930 / cybercrime.gov.in and block the number."],
  "hi": ["जवाब न दें, लिंक पर क्लिक न करें और मैसेज वाले नंबर पर कॉल न करें।", "OTP, PIN, CVV या आधार किसी को न बताएं - बैंक कभी नहीं मांगते।",
         "सिर्फ आधिकारिक ऐप या कार्ड पर छपे नंबर से जांच करें।", "1930 / cybercrime.gov.in पर रिपोर्ट करें और नंबर ब्लॉक करें।"]},
 "port_scan": {
  "en": ["Block the source IP at the router/firewall.", "Close any ports you do not need (check with `ss -tlnp`).", "Keep device firmware and router updated."],
  "hi": ["राउटर/फ़ायरवॉल पर उस स्रोत IP को ब्लॉक करें।", "जो पोर्ट ज़रूरी नहीं हैं उन्हें बंद करें।", "डिवाइस और राउटर का फर्मवेयर अपडेट रखें।"]},
 "dos_flood": {
  "en": ["Rate-limit or block the source IP at the router.", "Restart the affected service/device if it is unresponsive.", "Contact your ISP if the flood continues."],
  "hi": ["राउटर पर उस IP को ब्लॉक या रेट-लिमिट करें।", "अगर डिवाइस जवाब नहीं दे रहा तो रीस्टार्ट करें।", "हमला जारी रहे तो ISP से संपर्क करें।"]},
 "brute_force": {
  "en": ["Block the source IP and disable password login for SSH/RDP (use keys).", "Change the targeted account's password immediately.", "Do not expose SSH/RDP/Telnet to the internet; use a VPN."],
  "hi": ["स्रोत IP ब्लॉक करें और SSH/RDP पर पासवर्ड लॉगिन बंद करें।", "जिस अकाउंट पर हमला हुआ उसका पासवर्ड तुरंत बदलें।", "SSH/RDP/Telnet को इंटरनेट पर खुला न रखें; VPN इस्तेमाल करें।"]},
 "botnet_c2": {
  "en": ["Disconnect the affected device from the network.", "Run a malware scan / factory-reset IoT devices.", "Block the remote address and change passwords used on that device."],
  "hi": ["प्रभावित डिवाइस को नेटवर्क से हटा दें।", "मैलवेयर स्कैन करें / IoT डिवाइस फ़ैक्टरी-रीसेट करें।", "रिमोट पते को ब्लॉक करें और उस डिवाइस के पासवर्ड बदलें।"]},
 "new_device": {
  "en": ["Check whether you recognise this device (a new phone, TV, laptop or a guest).", "If you do not recognise it, change your Wi-Fi password and remove it from the router's device list.", "If it is yours, press 'Trust' so it is not flagged again."],
  "hi": ["देखें कि क्या आप इस डिवाइस को पहचानते हैं (नया फ़ोन, टीवी, लैपटॉप या मेहमान)।", "अगर नहीं पहचानते तो Wi-Fi पासवर्ड बदलें और राउटर की डिवाइस सूची से इसे हटाएं।", "अगर यह आपका है तो 'Trust' दबाएं ताकि दोबारा फ़्लैग न हो।"]},
 "unknown_anomaly": {
  "en": ["Check which device produced this traffic and whether you recognise it.", "Monitor it for a while; block it if it repeats.", "Keep a copy of the log for investigation."],
  "hi": ["देखें कि यह ट्रैफ़िक किस डिवाइस से आया और क्या आप उसे पहचानते हैं।", "कुछ समय निगरानी रखें; दोहराए तो ब्लॉक करें।", "जांच के लिए लॉग सुरक्षित रखें।"]},
}
TITLES = {
 "phishing_url": ("Phishing link detected", "फ़िशिंग लिंक मिला"), "scam_sms": ("Scam message detected", "स्कैम मैसेज मिला"),
 "port_scan": ("Port scan detected", "पोर्ट स्कैन मिला"), "dos_flood": ("Flood / DoS attack detected", "फ्लड/DoS हमला मिला"),
 "brute_force": ("Password-guessing attack", "पासवर्ड ब्रूट-फ़ोर्स हमला"), "botnet_c2": ("Possible malware 'phoning home'", "संभावित मैलवेयर कमांड-कनेक्शन"),
 "new_device": ("New unknown device on your network", "आपके नेटवर्क पर नया अनजान डिवाइस"), "unknown_anomaly": ("Unusual network behaviour", "असामान्य नेटवर्क गतिविधि")}
SAFE = ("No threat found.", "कोई खतरा नहीं मिला।")
HI_EVIDENCE = {  # English evidence phrase -> Hindi
 "uses a raw IP address": "डोमेन की जगह सीधा IP पता इस्तेमाल हुआ है", "contains '@'": "'@' है जो असली गंतव्य छुपा सकता है",
 "mentions a well-known brand": "किसी जानी-मानी कंपनी का नाम है पर यह उसका आधिकारिक डोमेन नहीं है",
 "top-level domain commonly abused": "ऐसा डोमेन एक्सटेंशन जिसका स्कैमर अक्सर दुरुपयोग करते हैं", "several urgency/credential": "कई जल्दबाज़ी/क्रेडेंशियल शब्द हैं (login, verify, kyc...)",
 "punycode": "नकली दिखने वाले अक्षरों (punycode) का इस्तेमाल है", "deep chain of subdomains": "असामान्य रूप से कई सबडोमेन हैं",
 "shortened link": "छोटा किया हुआ लिंक है जो असली पता छुपाता है", "not using HTTPS": "HTTPS इस्तेमाल नहीं हो रहा", "many hyphens": "डोमेन में बहुत सारे हाइफ़न हैं",
 "official domain of a known brand": "यह जानी-मानी कंपनी का आधिकारिक डोमेन है",
 "false urgency": "जल्दबाज़ी का झूठा दबाव बनाता है", "sensitive info": "OTP/PIN/आधार/बैंक जानकारी मांगता है",
 "classic KYC scam": "अकाउंट/सिम बंद करने की धमकी (क्लासिक KYC स्कैम)", "prize or reward": "ऐसा इनाम का वादा जिसके लिए आपने आवेदन नहीं किया",
 "easy money": "आसान कमाई का लालच या छोटी 'फ़ीस' की मांग", "contains a link": "लिंक है (अनजान मैसेज के लिंक पर कभी क्लिक न करें)", "call an unknown number": "अनजान नंबर पर कॉल करने को कहता है",
 "tiny probe packets": "बहुत छोटे जांच-पैकेट भेजे जिनका लगभग कोई जवाब नहीं आया", "many different ports": "कई अलग-अलग पोर्ट छुए", "probed": "इस होस्ट ने 10 सेकंड में कई पोर्ट जांचे",
 "extreme number of packets": "कुछ ही सेकंड में बेहद ज़्यादा पैकेट भेजे", "almost no responses": "लगभग कोई जवाब वापस नहीं आया",
 "repeated short login-style": "बार-बार छोटे लॉगिन जैसे प्रयास किए", "login service port": "लॉगिन सर्विस पोर्ट (SSH/FTP/RDP/Telnet) को निशाना बनाया",
 "first time this device": "यह डिवाइस पहली बार आपके नेटवर्क पर दिखा है", "heartbeat": "लंबा, नियमित 'हार्टबीट' जैसा कनेक्शन रखा", "unusual port": "रिमोट-कंट्रोल जैसा असामान्य पोर्ट इस्तेमाल किया",
 "statistically unusual": "यह व्यवहार इस नेटवर्क के सामान्य ट्रैफ़िक से काफ़ी अलग है"}


def localize(evidence, lang):
    if lang != "hi": return evidence
    return [next((v for k, v in HI_EVIDENCE.items() if k in e), e) for e in evidence]


def key_of(f):
    if f["type"] == "network_flow": return None if f["label"] == "benign" else f["label"]
    return f["type"] if f["label"] in ("malicious", "scam") else None


def severity(score):
    return "high" if score >= 0.85 else "medium" if score >= 0.6 else "low"


class LlamaExecuTorch:
    """Thin wrapper around ExecuTorch's `llama_main` runner binary.
    Env vars: TRINETRA_LLAMA_BIN, TRINETRA_LLAMA_MODEL (.pte), TRINETRA_LLAMA_TOKENIZER (tokenizer.model)."""
    def __init__(self, binary=None, model=None, tokenizer=None, seq_len=160, timeout=60):
        self.bin = binary or os.environ.get("TRINETRA_LLAMA_BIN") or shutil.which("llama_main")
        self.model = model or os.environ.get("TRINETRA_LLAMA_MODEL")
        self.tok = tokenizer or os.environ.get("TRINETRA_LLAMA_TOKENIZER")
        self.seq_len, self.timeout = seq_len, timeout

    @property
    def available(self):
        return all(p and os.path.exists(p) for p in (self.bin, self.model, self.tok))

    def generate(self, system, user):
        prompt = ("<|start_header_id|>system<|end_header_id|>\n\n" + system + "<|eot_id|>"
                  "<|start_header_id|>user<|end_header_id|>\n\n" + user + "<|eot_id|>"
                  "<|start_header_id|>assistant<|end_header_id|>\n\n")
        r = subprocess.run([self.bin, f"--model_path={self.model}", f"--tokenizer_path={self.tok}",
                            f"--prompt={prompt}", f"--seq_len={self.seq_len}", "--temperature=0.2"],
                           capture_output=True, text=True, timeout=self.timeout)
        out = r.stdout; self.last_stats = None
        for ln in (r.stdout + r.stderr).splitlines():          # ExecuTorch runner prints timing stats as 'PyTorchObserver {json}'
            if ln.startswith("PyTorchObserver"):
                try: self.last_stats = json.loads(ln[len("PyTorchObserver"):].strip())
                except ValueError: pass
        if "assistant" in out: out = out.split("assistant")[-1]
        out = out.split("PyTorchObserver")[0].replace("<|eot_id|>", "").strip()
        return out


SYSTEM = ("You are Trinetra, a calm digital-safety assistant running fully offline on a small device. "
          "A detector has ALREADY decided the verdict; do not change it. In at most 3 short sentences, explain to a "
          "non-technical person why this was flagged, using ONLY the evidence given. Do not invent facts, numbers or links.")


class Advisor:
    def __init__(self, llama: LlamaExecuTorch | None = None):
        self.llama = llama if llama is not None else LlamaExecuTorch()

    @property
    def mode(self):
        return "llama-executorch" if self.llama.available else "template"

    def _template_explain(self, f, lang):
        k = key_of(f); i = 1 if lang == "hi" else 0
        if k is None: return SAFE[i]
        ev = localize(f.get("evidence", []), lang)
        if lang == "hi":
            return "यह इसलिए संदिग्ध है:" if ev else "यह पैटर्न खतरनाक गतिविधि से मेल खाता है।"
        return "Why this was flagged:" if ev else "This matches a known attack pattern."

    def advise(self, finding: dict, lang: str = "en", use_llm: bool = True):
        k = key_of(finding); i = 1 if lang == "hi" else 0
        res = {"verdict": "threat" if k else "safe", "title": TITLES[k][i] if k else SAFE[i],
               "severity": severity(finding["score"]) if k else "none",
               "actions": PLAYBOOK[k][lang if lang in ("en", "hi") else "en"] if k else [], "source": "template"}
        res["explanation"] = self._template_explain(finding, lang); res["evidence_local"] = localize(finding.get("evidence", []), lang) if k else []
        if k and use_llm and self.llama.available:
            try:
                lang_name = "Hindi (Devanagari)" if lang == "hi" else "English"
                user = (f"Verdict: {TITLES[k][0]} (confidence {finding['score']:.0%}).\nEvidence: " +
                        "; ".join(finding.get("evidence", [])) + f"\nReply in {lang_name}.")
                txt = self.llama.generate(SYSTEM, user)
                if len(txt) > 20: res["explanation"], res["source"] = textwrap.shorten(txt, 600), "llama-executorch"
            except Exception as e:  # never let the LLM break the security pipeline
                res["llm_error"] = str(e)[:120]
        return res
