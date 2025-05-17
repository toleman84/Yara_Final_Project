#!/usr/bin/env python3
import subprocess
import os

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
            # Call the sigma.exe CLI directly
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

            with open(output_path, "w", encoding="utf-8") as out_file:
                out_file.write(result.stdout)

            print(f"[✔] Compiled: {filename} → {output_path}")

        except subprocess.CalledProcessError as e:
            print(f"[✗] Failed to compile {filename}:\n{e.stderr}")
