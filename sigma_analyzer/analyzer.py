#!/usr/bin/env python3

import os
import json
import logging
import time
from datetime import datetime, timedelta
import requests

LOG_DIR = "/var/log/sigma"
COMPILED_DIR = "/app/compiled"
OUTPUT_FILE = os.path.join(LOG_DIR, "analyzer_output.json")

LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100") 
QUERY_ENDPOINT = f"{LOKI_URL}/loki/api/v1/query_range"

LOG_LEVEL = logging.DEBUG

# Ensure log directory exists BEFORE configuring logging
os.makedirs(LOG_DIR, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(LOG_DIR, "analyzer.log"))
    ]
)

def load_compiled_rules():
    rules = {}
    for filename in os.listdir(COMPILED_DIR):
        if filename.endswith(".logql"):
            path = os.path.join(COMPILED_DIR, filename)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    query = f.read().strip()
                    rules[filename] = query
                    logging.debug(f"Loaded rule: {filename}")
            except Exception as e:
                logging.error(f"Failed to load rule {filename}: {e}")
    return rules

def query_loki(logql, start, end, retries=3):
    params = {
        "query": logql,
        "start": str(int(start.timestamp() * 1e9)),  # nanoseconds
        "end": str(int(end.timestamp() * 1e9)),
        "limit": "1000"
    }
    attempt = 0
    while attempt < retries:
        try:
            resp = requests.get(QUERY_ENDPOINT, params=params, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            logging.error(f"Loki query failed (attempt {attempt+1}): {e}")
            time.sleep(2 ** attempt)
            attempt += 1
    logging.error("Max retries reached, giving up on query.")
    return None

def parse_results(rule_name, result_json):
    matches = []
    if not result_json:
        return matches
    data = result_json.get("data", {})
    result = data.get("result", [])
    for entry in result:
        stream = entry.get("stream", {})
        values = entry.get("values", [])
        for timestamp, log_line in values:
            ts = datetime.fromtimestamp(int(timestamp) / 1e9).isoformat()
            matches.append({
                "rule": rule_name,
                "timestamp": ts,
                "log": log_line,
                "labels": stream
            })
    return matches


def main():
    try:
        logging.info("Starting Sigma Analyzer")

        # Load all compiled LogQL rules
        rules = load_compiled_rules()
        if not rules:
            logging.warning("No compiled rules found, exiting.")
            return

        # Query time window: last 5 minutes
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=5)

        all_matches = []

        for rule_name, logql in rules.items():
            logging.info(f"Querying Loki for rule: {rule_name}")
            result_json = query_loki(logql, start_time, end_time)
            matches = parse_results(rule_name, result_json)
            logging.info(f"Found {len(matches)} matches for {rule_name}")
            all_matches.extend(matches)

        # Write all matches to JSON output
        try:
            with open(OUTPUT_FILE, "w", encoding="utf-8") as out_f:
                for match in all_matches:
                    out_f.write(json.dumps(match) + "\n")
            logging.info(f"Analysis complete, results written to {OUTPUT_FILE}")
        except Exception as e:
            logging.error(f"Failed to write output file: {e}")

    except Exception as e:
        logging.error(f"Critical error in main execution: {e}", exc_info=True)
        raise  # Re-raise to ensure container restart if needed

if __name__ == "__main__":
    while True:
        try:
            main()
            # Sleep before next execution cycle (e.g., 5 minutes)
            time.sleep(300)
        except KeyboardInterrupt:
            logging.info("Shutting down gracefully...")
            break
        except Exception as e:
            logging.error(f"Fatal error: {e}", exc_info=True)
            logging.info("Restarting analyzer in 60 seconds...")
            time.sleep(60)
    
    main()