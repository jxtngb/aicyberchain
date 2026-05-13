import pyshark
import pandas as pd

capture = pyshark.FileCapture("traffic.pcap")
data = []

for pkt in capture:
    try:
        data.append({
            "source_ip": pkt.ip.src,
            "destination_ip": pkt.ip.dst,
            "protocol": pkt.transport_layer,
            "packet_size": int(pkt.length)
        })
    except:
        pass

df = pd.DataFrame(data)
df.to_csv("traffic_data.csv", index=False)
print("Saved traffic_data.csv")
