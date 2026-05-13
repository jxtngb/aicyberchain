# capture_logs.py
# Captures live packets (safe local capture) and converts them into ML-ready CSV.

from scapy.all import sniff, wrpcap
import pandas as pd
import time

PCAP_FILE = "capture.pcap"
CSV_FILE = "packet_logs.csv"

# -----------------------
# Packet Capture Function
# -----------------------
def capture_packets(duration=10):
    print(f"Capturing packets for {duration} seconds...")
    packets = sniff(timeout=duration)
    wrpcap(PCAP_FILE, packets)
    print(f"Saved pcap: {PCAP_FILE}")
    return packets

# -----------------------
# Packet Parser
# -----------------------
def convert_pcap_to_csv(packets):
    rows = []

    for pkt in packets:
        row = {
            "timestamp": pkt.time,
            "src": pkt[0][1].src if pkt.haslayer("IP") else None,
            "dst": pkt[0][1].dst if pkt.haslayer("IP") else None,
            "proto": pkt.lastlayer().name,
            "length": len(pkt),
        }
        rows.append(row)

    df = pd.DataFrame(rows)
    df.to_csv(CSV_FILE, index=False)
    print(f"Saved CSV logs: {CSV_FILE}")
    return df


if __name__ == "__main__":
    pkts = capture_packets(duration=10)
    df = convert_pcap_to_csv(pkts)
    print(df.head())
