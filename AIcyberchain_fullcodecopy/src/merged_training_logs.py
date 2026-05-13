# merged_training_logs.py
import pandas as pd

ATTACK_FILE = "synthetic_attacks.csv"
PCAP_FILE = "packet_logs.csv"
OUT_FILE = "training_dataset.csv"

# Combine and label data
def merge():
    df_attacks = pd.read_csv(ATTACK_FILE)
    df_packets = pd.read_csv(PCAP_FILE)

    df_packets["attack_type"] = "normal"
    
    merged = pd.concat([df_attacks, df_packets], ignore_index=True)
    merged.to_csv(OUT_FILE, index=False)

    print(f"Merged training dataset saved: {OUT_FILE}")
    print(merged.head())

if __name__ == "__main__":
    merge()
