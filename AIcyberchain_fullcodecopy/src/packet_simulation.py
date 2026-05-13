from scapy.all import IP, TCP, send

packet = IP(dst="127.0.0.1") / TCP(dport=8080, flags="S")
send(packet, count=5, inter=1)

print("Packets sent safely")
