# attack_generator.py
# Academic-only simulated attack dataset generator
# No network interaction. Only synthetic attack samples are created.

import random
import string
import time
import json
import pandas as pd

# -------------------------
# SQL Injection Payloads
# -------------------------
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
    "' UNION SELECT * FROM users --",
    "\" OR \"\"=\"",
    "' OR ''='",
    "') OR ('1'='1",
]

# -------------------------
# Fuzz Payloads (Random)
# -------------------------
FUZZ_CHARS = list(string.ascii_letters + string.digits + "!@#$%^&*(){}[]<>?/~`")

def generate_fuzz_string(min_len=20, max_len=120):
    length = random.randint(min_len, max_len)
    return ''.join(random.choice(FUZZ_CHARS) for _ in range(length))

# -------------------------
# DDoS-like Synthetic Traffic
# -------------------------
def generate_ddos_packets(count=500):
    packets = []
    for _ in range(count):
        packets.append({
            "packet_size": random.randint(40, 120),   # small repetitive packet size
            "flags": "SYN",
            "src_port": random.randint(1024, 65535),
            "dst_port": 80,
            "timestamp": time.time(),
            "attack_type": "ddos"
        })
    return packets

# -------------------------
# Main data generator
# -------------------------
def generate_attack_dataset(samples=200):
    rows = []

    for _ in range(samples):
        choice = random.choice(["sqli", "fuzz", "ddos"])

        if choice == "sqli":
            payload = random.choice(SQLI_PAYLOADS)
            rows.append({
                "timestamp": time.time(),
                "payload": payload,
                "length": len(payload),
                "attack_type": "sqli"
            })

        elif choice == "fuzz":
            payload = generate_fuzz_string()
            rows.append({
                "timestamp": time.time(),
                "payload": payload,
                "length": len(payload),
                "attack_type": "fuzz"
            })

        elif choice == "ddos":
            # Single synthetic entry (summary)
            pkt = generate_ddos_packets(1)[0]
            rows.append(pkt)

        time.sleep(0.01)

    df = pd.DataFrame(rows)
    df.to_csv("synthetic_attacks.csv", index=False)
    return df


if __name__ == "__main__":
    df = generate_attack_dataset(500)
    print("Dataset generated: synthetic_attacks.csv")
    print(df.head())
