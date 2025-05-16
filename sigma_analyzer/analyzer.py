#!/usr/bin/env python3
import time
import glob
import yaml
import requests
import os

# ── Load config ───────────────────────────────────────────────────────────────
with open('loki-backend.yaml') as f:
    cfg = yaml.safe_load(f)

LOKI_URL     = cfg['loki']['url'].rstrip('/') + '/loki/api/v1/query_range'
QUERY_LABELS = cfg['loki']['labels']       # e.g. {'job': ['postfix','scanner','sigma_scanner']}
FETCH_INT    = cfg.get('fetch_interval', 60)
COMPILED_DIR = cfg.get('compiled_dir', 'compiled')

# Build a LogQL selector from your labels block
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
    for path in glob.glob(pattern):
        name = os.path.splitext(os.path.basename(path))[0]
        with open(path) as f:
            # Prepend the base selector if not already included
            q = f.read().strip()
            if not q.startswith('{'):
                q = f"{BASE_SELECTOR} | {q}"
        queries[name] = q
    return queries

# ── Poll Loki and print alerts ────────────────────────────────────────────────
def fetch_and_alert(queries):
    for name, query in queries.items():
        resp = requests.get(LOKI_URL, params={'query': query, 'limit': 50})
        data = resp.json().get('data', {}).get('result', [])
        for stream in data:
            for ts, line in stream.get('values', []):
                print(f"[ALERT] {name} @ {ts}: {line}")

# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    queries = load_compiled_queries()
    if not queries:
        print("No compiled queries found in", COMPILED_DIR)
        return

    print(f"Loaded {len(queries)} compiled rules. Polling Loki every {FETCH_INT}s…")
    while True:
        fetch_and_alert(queries)
        time.sleep(FETCH_INT)

if __name__ == '__main__':
    main()
