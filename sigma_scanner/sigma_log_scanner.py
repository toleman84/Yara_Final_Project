#!/usr/bin/env python3
"""
Sigma log scanner: tails mail_scanner.json and evaluates Sigma rules.
Logs alerts to /logs/sigma/sigma_alerts.log for Promtail ingestion.
"""

import os, time, json, logging, re, yaml
from typing import Dict, Any, List

# ======================= Config ==========================
LOG_FILE = "/var/log/mail_scanner.json"       # From YARA scanner
SIGMA_DIR = "/app/rules/sigma"                # Where sigma YAMLs are stored
ALERT_LOG = "/logs/sigma/sigma_alerts.log"    # Promtail watches this

# ===================== Setup Logging =====================
os.makedirs("/logs/sigma", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(ALERT_LOG),
        logging.StreamHandler()
    ]
)

# ==================== Sigma Rule Class ===================
class SigmaRule:
    def __init__(self, data: Dict[str, Any]):
        self.title = data.get("title", "Unnamed Rule")
        self.detection = data.get("detection", {})

    def evaluate(self, evt: Dict[str, Any]) -> bool:
        # Simple keyword match in body
        if "keywords" in self.detection:
            body = evt.get("subject", "").lower() + " " + evt.get("body", "").lower()
            for kw in self.detection["keywords"]:
                if kw.lower() in body:
                    return True
        # Field-specific pattern match
        if "fields" in self.detection:
            for field, patterns in self.detection["fields"].items():
                value = str(evt.get(field, "")).lower()
                pattern_list = patterns if isinstance(patterns, list) else [patterns]
                for pat in pattern_list:
                    if re.search(pat.lower(), value):
                        return True
        return False

# ==================== Load Sigma Rules ====================
def load_sigma_rules() -> List[SigmaRule]:
    rules = []
    for root, _, files in os.walk(SIGMA_DIR):
        for fname in files:
            if fname.endswith((".yml", ".yaml")):
                try:
                    with open(os.path.join(root, fname)) as f:
                        data = yaml.safe_load(f)
                    rules.append(SigmaRule(data))
                except Exception as e:
                    logging.error(f"Failed to load {fname}: {e}")
    logging.info(f"Loaded {len(rules)} Sigma rules")
    return rules

# ==================== Tail Log File ====================
def follow_log(path: str):
    if not os.path.exists(path):
        open(path, "w").close()
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line

# ======================== Main =========================
def main():
    rules = load_sigma_rules()
    for line in follow_log(LOG_FILE):
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        for rule in rules:
            try:
                if rule.evaluate(evt):
                    logging.warning(f"Sigma Alert: {rule.title} | {evt.get('sender')} → {evt.get('recipient')}")
            except Exception as e:
                logging.error(f"Error in rule '{rule.title}': {e}")

if __name__ == "__main__":
    main()
