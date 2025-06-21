#!/usr/bin/env python3
import subprocess
import os
import re

SIGMA_DIR   = "sigma_rules"
CONFIG_PATH = "loki-backend.yaml"
OUTPUT_DIR  = "compiled"

os.makedirs(OUTPUT_DIR, exist_ok=True)

for filename in os.listdir(SIGMA_DIR):
    if filename.endswith((".yml", ".yaml")):
        input_path  = os.path.join(SIGMA_DIR, filename)
        output_path = os.path.join(
            OUTPUT_DIR,
            filename.rsplit(".", 1)[0] + ".logql"
        )

        try:
            # Call sigma.exe CLI
            result = subprocess.run(
                [
                    "sigma.exe", "convert",
                    "-t", "loki",
                    input_path
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )

            # Patch: replace '| logfmt' with '| json' and fix regex quotes
            query = result.stdout
            query = query.replace("| logfmt", "| json")
            query = query.replace("=~`", "=~\"").replace("`", "\"")

            # Insert '| json' before '|~' if 'line_format' present and '| json' missing
            if "line_format" in query and "| json" not in query:
                # Insert '| json' before the first '|~' or similar operator
                query = re.sub(r"(\|~)", r"| json \1", query, count=1)

            with open(output_path, "w", encoding="utf-8") as out_file:
                out_file.write(query)

            print(f"[✔] Compiled: {filename} → {output_path}")

        except subprocess.CalledProcessError as e:
            print(f"[✗] Failed to compile {filename}:\n{e.stderr}")
