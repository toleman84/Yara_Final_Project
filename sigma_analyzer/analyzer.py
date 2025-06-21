#!/usr/bin/env python3
"""
Sigma Analyzer for Loki Logs (JSON Enhanced)
- Structured JSON logging for Loki/Grafana
- Threaded query execution
- Dynamic time windows
- Built-in alerting and log rotation
"""

import os
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import requests
from logging.handlers import RotatingFileHandler
from pythonjsonlogger import jsonlogger

# Configuration (override with environment variables)
CONFIG = {
    "LOG_DIR": os.getenv("LOG_DIR", "/var/log/sigma"),
    "COMPILED_RULES_DIR": os.getenv("COMPILED_DIR", "/app/compiled"),
    "LOKI_URL": os.getenv("LOKI_URL", "http://loki:3100"),
    "QUERY_WINDOW": int(os.getenv("QUERY_WINDOW_MINUTES", "5")),
    "SLEEP_INTERVAL": int(os.getenv("SLEEP_SECONDS", "300")),
    "ALERT_WEBHOOK": os.getenv("ALERT_WEBHOOK", ""),
    "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO").upper(),
    "LOG_JSON": os.getenv("LOG_JSON", "true").lower() == "true"
}

# Global setup
QUERY_ENDPOINT = f"{CONFIG['LOKI_URL']}/loki/api/v1/query_range"
OUTPUT_TEMPLATE = "analyzer_output_{timestamp}.json"

class StructuredLogger:
    """Custom JSON logger for Loki/Grafana compatibility"""
    def __init__(self):
        self.logger = logging.getLogger("sigma_analyzer")
        self.logger.setLevel(CONFIG["LOG_LEVEL"])
        self._setup_handlers()

    def _setup_handlers(self):
        os.makedirs(CONFIG["LOG_DIR"], exist_ok=True)
        
        formatter = jsonlogger.JsonFormatter(
            fmt="%(asctime)s %(levelname)s %(message)s %(name)s %(module)s %(funcName)s",
            rename_fields={
                "levelname": "level",
                "asctime": "timestamp",
                "funcName": "function"
            },
            datefmt="%Y-%m-%d %H:%M:%S,%f"
        )

        # File handler (JSON format)
        file_handler = RotatingFileHandler(
            os.path.join(CONFIG["LOG_DIR"], "analyzer.json"),
            maxBytes=10*1024*1024,
            backupCount=5
        )
        file_handler.setFormatter(formatter)

        # Console handler (optional, for debugging)
        console_handler = logging.StreamHandler()
        if CONFIG["LOG_JSON"]:
            console_handler.setFormatter(formatter)
        else:
            console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def log(self, level, message, **extra):
        """Structured logging with additional context"""
        extra.update({
            "service": "sigma_analyzer",
            "environment": os.getenv("ENVIRONMENT", "production")
        })
        getattr(self.logger, level.lower())(message, extra=extra)

# Initialize logger
logger = StructuredLogger()

def load_compiled_rules():
    """Load all .logql files from rules directory"""
    rules = {}
    try:
        for filename in os.listdir(CONFIG["COMPILED_RULES_DIR"]):
            if filename.endswith(".logql"):
                path = os.path.join(CONFIG["COMPILED_RULES_DIR"], filename)
                with open(path, "r") as f:
                    rules[filename] = f.read().strip()
                logger.log("DEBUG", "Loaded rule", rule=filename, path=path)
        return rules
    except Exception as e:
        logger.log("ERROR", "Rule loading failed", error=str(e), exc_info=True)
        return {}

def query_loki(logql_query, start_time, end_time):
    """Execute LogQL query against Loki with retries"""
    params = {
        "query": logql_query,
        "start": str(int(start_time.timestamp() * 1e9)),
        "end": str(int(end_time.timestamp() * 1e9)),
        "limit": "5000"
    }
    
    for attempt in range(3):
        try:
            response = requests.get(QUERY_ENDPOINT, params=params, timeout=15)
            response.raise_for_status()
            return response.json().get("data", {}).get("result", [])
        except requests.RequestException as e:
            logger.log("WARNING", "Query attempt failed", 
                      attempt=attempt+1, 
                      error=str(e),
                      query=logql_query)
            time.sleep(2 ** attempt)
    return None

def process_rule(rule_name, logql, start_time, end_time):
    """Thread-safe rule processing with structured logging"""
    logger.log("INFO", "Executing rule", 
               rule=rule_name, 
               start_time=start_time.isoformat(),
               end_time=end_time.isoformat())
    
    results = query_loki(logql, start_time, end_time)
    matches = parse_results(rule_name, results)
    
    if matches:
        logger.log("INFO", "Rule matches found",
                  rule=rule_name,
                  match_count=len(matches))
    return matches

def parse_results(rule_name, loki_results):
    """Extract and structure matches from Loki response"""
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
                "labels": labels,
                "type": "sigma_alert"
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
                json={
                    "text": f"🚨 Critical threat detected: {match['rule']}",
                    "data": match
                }
            )
            logger.log("INFO", "Alert sent", 
                      rule=match["rule"],
                      webhook=CONFIG["ALERT_WEBHOOK"])
        except Exception as e:
            logger.log("ERROR", "Alert failed", 
                      error=str(e),
                      rule=match["rule"])

def write_output(matches):
    """Write results with timestamped filename (JSON Lines format)"""
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
        
        logger.log("INFO", "Results written", 
                  output_file=filename,
                  match_count=len(matches))
    except Exception as e:
        logger.log("ERROR", "Failed to write results", 
                  error=str(e),
                  output_path=path)

def main_loop():
    """Continuous analysis loop with dynamic time windows"""
    last_run_time = datetime.now(timezone.utc) - timedelta(minutes=CONFIG["QUERY_WINDOW"])
    rules = load_compiled_rules()
    rules_last_reloaded = time.time()
    
    while True:
        try:
            # Reload rules every hour
            if time.time() - rules_last_reloaded > 3600:
                logger.log("INFO", "Reloading rules")
                rules = load_compiled_rules()
                rules_last_reloaded = time.time()
            
            # Calculate time window
            start_time = last_run_time
            end_time = datetime.now(timezone.utc)
            logger.log("INFO", "Processing time window", 
                      start_time=start_time.isoformat(),
                      end_time=end_time.isoformat())
            
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
            logger.log("INFO", "Sleeping until next cycle", 
                      sleep_seconds=CONFIG["SLEEP_INTERVAL"])
            time.sleep(CONFIG["SLEEP_INTERVAL"])
            
        except KeyboardInterrupt:
            logger.log("INFO", "Shutdown requested")
            break
        except Exception as e:
            logger.log("ERROR", "Fatal error in main loop", 
                      error=str(e),
                      exc_info=True)
            time.sleep(60)

if __name__ == "__main__":
    logger.log("INFO", "Service starting", 
              config=CONFIG,
              version="1.0.0")
    main_loop()
    logger.log("INFO", "Service stopped")