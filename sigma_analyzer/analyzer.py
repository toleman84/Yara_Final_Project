#!/usr/bin/env python3
"""
Sigma Analyzer for Loki Logs
- Queries Loki using compiled LogQL rules
- Runs continuously with dynamic time windows
- Threaded queries for performance
- Built-in alerting and rotation
"""

import os
import json
import logging
import time
from datetime import datetime, timedelta, timezone 
from concurrent.futures import ThreadPoolExecutor
import requests
from logging.handlers import RotatingFileHandler

# Configuration (override with environment variables)
CONFIG = {
    "LOG_DIR": os.getenv("LOG_DIR", "/var/log/sigma"),
    "COMPILED_RULES_DIR": os.getenv("COMPILED_DIR", "/app/compiled"),
    "LOKI_URL": os.getenv("LOKI_URL", "http://loki:3100"),
    "QUERY_WINDOW": int(os.getenv("QUERY_WINDOW_MINUTES", "5")),  # Default 5 min
    "SLEEP_INTERVAL": int(os.getenv("SLEEP_SECONDS", "300")),     # Default 5 min
    "ALERT_WEBHOOK": os.getenv("ALERT_WEBHOOK", ""),             # Slack/MS Teams URL
    "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO").upper()
}

# Global setup
QUERY_ENDPOINT = f"{CONFIG['LOKI_URL']}/loki/api/v1/query_range"
OUTPUT_TEMPLATE = "analyzer_output_{timestamp}.json"

# Initialize logging
os.makedirs(CONFIG["LOG_DIR"], exist_ok=True)
logging.basicConfig(
    level=CONFIG["LOG_LEVEL"],
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        RotatingFileHandler(
            os.path.join(CONFIG["LOG_DIR"], "analyzer.log"),
            maxBytes=10*1024*1024,  # 10MB rotation
            backupCount=5
        ),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_compiled_rules():
    """Load all .logql files from rules directory"""
    rules = {}
    try:
        for filename in os.listdir(CONFIG["COMPILED_RULES_DIR"]):
            if filename.endswith(".logql"):
                path = os.path.join(CONFIG["COMPILED_RULES_DIR"], filename)
                with open(path, "r") as f:
                    rules[filename] = f.read().strip()
                logger.debug(f"Loaded rule: {filename}")
    except Exception as e:
        logger.error(f"Rule loading failed: {e}")
    return rules

def query_loki(logql_query, start_time, end_time):
    """Execute LogQL query against Loki with retries"""
    params = {
        "query": logql_query,
        "start": str(int(start_time.timestamp() * 1e9)),
        "end": str(int(end_time.timestamp() * 1e9)),
        "limit": "5000"  # Increase for dense logs
    }
    
    for attempt in range(3):
        try:
            response = requests.get(QUERY_ENDPOINT, params=params, timeout=15)
            response.raise_for_status()
            return response.json().get("data", {}).get("result", [])
        except requests.RequestException as e:
            logger.warning(f"Query attempt {attempt+1} failed: {str(e)}")
            time.sleep(2 ** attempt)
    return None

def process_rule(rule_name, logql, start_time, end_time):
    """Thread-safe rule processing"""
    logger.info(f"Executing rule: {rule_name}")
    results = query_loki(logql, start_time, end_time)
    matches = parse_results(rule_name, results)
    
    # NEW: Add logging for match count here
    if matches:
        logger.info(f"Found {len(matches)} matches for {rule_name}")
    else:
        logger.debug(f"No matches found for {rule_name}")  # Optional debug line
    
    return matches

def parse_results(rule_name, loki_results):
    """Extract matches from Loki response"""
    matches = []
    if not loki_results:
        return matches
    
    for stream_result in loki_results:
        labels = stream_result.get("stream", {})
        for timestamp, log_line in stream_result.get("values", []):
            matches.append({
                "rule": rule_name,
                "timestamp": datetime.fromtimestamp(int(timestamp)/1e9).isoformat(),
                "log": log_line,
                "labels": labels
            })
    return matches

def trigger_alerts(matches):
    """Send high-severity matches to alerting webhook"""
    if not CONFIG["ALERT_WEBHOOK"]:
        return
    
    critical_matches = [m for m in matches if m["labels"].get("severity") == "critical"]
    for match in critical_matches:
        try:
            requests.post(
                CONFIG["ALERT_WEBHOOK"],
                json={"text": f"🚨 Critical threat detected: {match['rule']}"}
            )
        except Exception as e:
            logger.error(f"Alert failed: {e}")

def write_output(matches):
    """Write results with timestamped filename"""
    if not matches:
        return
    
    try:
        filename = OUTPUT_TEMPLATE.format(
            timestamp=datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        )
        path = os.path.join(CONFIG["LOG_DIR"], filename)
        
        with open(path, "w") as f:
            for match in matches:
                f.write(json.dumps(match) + "\n")
        logger.info(f"Wrote {len(matches)} matches to {filename}")
    except Exception as e:
        logger.error(f"Output write failed: {e}")

def main_loop():
    """Continuous analysis loop with dynamic time windows"""
    last_run_time = datetime.now(timezone.utc) - timedelta(minutes=CONFIG["QUERY_WINDOW"])
    rules = load_compiled_rules()
    rules_last_reloaded = time.time()
    
    while True:
        try:
            # Reload rules every hour
            if time.time() - rules_last_reloaded > 3600:
                logger.info("Reloading rules...")
                rules = load_compiled_rules()
                rules_last_reloaded = time.time()
            
            # Calculate time window
            start_time = last_run_time
            end_time = datetime.now(timezone.utc)
            logger.info(f"Processing window: {start_time} to {end_time}")
            
            # Parallel execution of rules
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [
                    executor.submit(
                        process_rule,
                        rule_name,
                        logql,
                        start_time,
                        end_time
                    ) for rule_name, logql in rules.items()
                ]
                
                all_matches = []
                for future in futures:
                    all_matches.extend(future.result())
            
            # Output and alerts
            trigger_alerts(all_matches)
            write_output(all_matches)
            
            # Prepare for next iteration
            last_run_time = end_time
            logger.info(f"Sleeping for {CONFIG['SLEEP_INTERVAL']} seconds")
            time.sleep(CONFIG["SLEEP_INTERVAL"])
            
        except KeyboardInterrupt:
            logger.info("Shutdown requested")
            break
        except Exception as e:
            logger.error(f"Fatal error: {e}", exc_info=True)
            logger.info("Restarting in 60 seconds...")
            time.sleep(60)

if __name__ == "__main__":
    logger.info("Starting Sigma Analyzer")
    logger.info(f"Configuration: {json.dumps(CONFIG, indent=2)}")
    main_loop()
    logger.info("Sigma Analyzer stopped")