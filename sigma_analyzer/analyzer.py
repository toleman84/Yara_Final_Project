#!/usr/bin/env python3
import time
import glob
import yaml
import requests
import os
import logging

# ── Setup Logging ─────────────────────────────────────────────────────────────
log_file = "/var/log/sigma-alerts.log"

# Configure two handlers
console_handler = logging.StreamHandler()
file_handler = logging.FileHandler(log_file)

# Level filters
console_handler.setLevel(logging.INFO)     # Show INFO+ in console
file_handler.setLevel(logging.WARNING)     # Only WARNING+ to file

# Custom formatter with rule context
formatter = logging.Formatter(
    '%(asctime)s [%(levelname)s] source=sigma rule=%(rule_name)s %(message)s',
    defaults={'rule_name': 'system'}  # Default for non-rule logs
)

# Apply formatter to both handlers
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

# Configure root logger
logging.basicConfig(
    level=logging.DEBUG,  # Base level (controlled by handlers)
    handlers=[console_handler, file_handler]
)

# ── Load config ───────────────────────────────────────────────────────────────
try:
    with open('loki-backend.yaml') as f:
        cfg = yaml.safe_load(f)
except Exception as e:
    logging.error("Failed to load configuration: %s", e)
    raise

LOKI_URL     = cfg['loki']['url'].rstrip('/') + '/loki/api/v1/query_range'
QUERY_LABELS = cfg['loki']['labels']
FETCH_INT    = cfg.get('fetch_interval', 60)
COMPILED_DIR = cfg.get('compiled_dir', 'compiled')

# Build LogQL selector
label_filters = []
for k, vs in QUERY_LABELS.items():
    if isinstance(vs, list):
        label_filters.append(f'{k}=~"{ "|".join(vs) }"')
    else:
        label_filters.append(f'{k}="{vs}"')
BASE_SELECTOR = '{' + ','.join(label_filters) + '}'

# ── Load compiled queries ─────────────────────────────────────────────────────
def load_compiled_queries():
    queries = {}
    pattern = os.path.join(COMPILED_DIR, '*.logql')
    logging.info("Loading compiled queries from '%s'", COMPILED_DIR)
    for path in glob.glob(pattern):
        name = os.path.splitext(os.path.basename(path))[0]
        try:
            with open(path) as f:
                q = f.read().strip()
                if not q.startswith('{'):
                    q = f"{BASE_SELECTOR} | {q}"
                queries[name] = q
                #logging.info("Loaded rule: %s", name, extra={'rule_name': name})
        except Exception as e:
            logging.warning("Failed to load %s: %s", path, e, extra={'rule_name': 'system'})
    return queries

# ── Wait for Loki ─────────────────────────────────────────────────────────────
def wait_for_loki(timeout=300, interval=5):
    start = time.time()
    LOKI_BASE_URL = cfg['loki']['url'].rstrip('/')
    health_url = f"{LOKI_BASE_URL}/ready"
    logging.info("Checking Loki readiness at %s", health_url)

    while time.time() - start < timeout:
        try:
            resp = requests.get(health_url, timeout=3)
            if resp.status_code == 200 and resp.text.strip() == "ready":
                logging.info("Loki is ready!")
                return
        except requests.exceptions.RequestException:
            pass
        elapsed = int(time.time() - start)
        logging.info("Waiting for Loki... (%ds elapsed)", elapsed)
        time.sleep(interval)

    logging.error("Loki failed to become ready within timeout")
    raise RuntimeError("Loki did not start in time.")

# ── Poll Loki ─────────────────────────────────────────────────────────────────
def fetch_and_alert(queries):
    for name, query in queries.items():
        try:
            alert_count = 0
            resp = requests.get(LOKI_URL, params={'query': query, 'limit': 50}, timeout=10)
            resp.raise_for_status()

            try:
                data = resp.json().get('data', {}).get('result', [])
            except ValueError:
                logging.warning(
                    "Invalid JSON response for query '%s': %.200s...",
                    name, resp.text,
                    extra={'rule_name': name}
                )
                continue

            if alert_count > 0:
                logging.info(
                    "Rule '%s' triggered %d alerts",
                    name, alert_count,
                    extra={'rule_name': name}
                )
                
        except Exception as e:
            logging.warning(
                "Error processing rule '%s': %s",
                name, e,
                extra={'rule_name': name}
            )
            continue 

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    logging.info("Starting Sigma Analyzer")
    queries = load_compiled_queries()

    if not queries:
        logging.warning("No compiled queries found")
        return

    logging.info("Loaded %d queries. Checking Loki readiness...", len(queries))
    wait_for_loki()

    logging.info("Starting polling loop (interval: %ds)", FETCH_INT)
    while True:
        try:
            fetch_and_alert(queries)
            time.sleep(FETCH_INT)
        except Exception as e:
            logging.error("Critical error: %s. Restarting...", e)
            time.sleep(FETCH_INT)

# ── Entrypoint ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()