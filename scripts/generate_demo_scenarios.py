import os
import time
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, wrpcap, Raw

def generate_ddos(base_time):
    packets = []
    # 500 SYN packets in 1 second
    for i in range(500):
        pkt = Ether()/IP(src="10.0.0.100", dst="192.168.1.50")/TCP(sport=10000, dport=80, flags="S")
        pkt.time = base_time + (i * 0.002)
        packets.append(pkt)
    return packets

def generate_c2(base_time):
    packets = []
    # 5 beacons, 60 seconds apart
    base_time = time.time() - 300
    for i in range(5):
        pkt = Ether()/IP(src="192.168.1.105", dst="198.51.100.10")/TCP(sport=55550+i, dport=443, flags="PA")/Raw(load="X"*100)
        pkt.time = base_time + (i * 60)
        packets.append(pkt)
    return packets

def generate_dga(base_time):
    packets = []
    # DNS queries for random looking domains
    import random
    import string
    for i in range(5):
        domain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=36)) + ".com"
        pkt = Ether()/IP(src="10.0.0.100", dst="8.8.8.8")/UDP(sport=33333+i, dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
        pkt.time = base_time + (i * 10)
        packets.append(pkt)
    return packets

def generate_recon(base_time):
    packets = []
    # Port scan
    for port in range(1, 100):
        pkt = Ether()/IP(src="192.168.1.200", dst="10.0.0.50")/TCP(sport=44444, dport=port, flags="S")
        pkt.time = base_time + (port * 0.1)
        packets.append(pkt)
    return packets

def generate_exfil(base_time):
    packets = []
    # 100 large packets outbound
    for i in range(100):
        pkt = Ether()/IP(src="192.168.1.105", dst="198.51.100.10")/TCP(sport=55555, dport=443, flags="PA")/Raw(load="X"*1400)
        pkt.time = base_time + (i * 0.01)
        packets.append(pkt)
    return packets

def generate_encrypted(base_time):
    packets = []
    # Generate an encrypted flow that lacks SNI and has suspicious lengths
    # We fake it using TCP port 443 and random sizes
    import random
    # Just 20 packets to port 443 with weird sizes
    for i in range(20):
        size = random.randint(100, 1000)
        pkt = Ether()/IP(src="192.168.1.110", dst="203.0.113.10")/TCP(sport=54321, dport=443, flags="PA")/Raw(load="Y"*size)
        pkt.time = base_time + (i * 0.5)
        packets.append(pkt)
    return packets

def main():
    print("Generating demo_six_threats.pcap...")
    all_packets = []
    base_time = time.time()
    
    all_packets.extend(generate_ddos(base_time))
    base_time += 10
    all_packets.extend(generate_c2(base_time))
    base_time += 110
    all_packets.extend(generate_dga(base_time))
    base_time += 20
    all_packets.extend(generate_recon(base_time))
    base_time += 10
    all_packets.extend(generate_exfil(base_time))
    base_time += 10
    all_packets.extend(generate_encrypted(base_time))
    
    # Sort packets by time
    all_packets.sort(key=lambda p: p.time)
    
    os.makedirs("data/samples", exist_ok=True)
    wrpcap("data/samples/demo_six_threats.pcap", all_packets)
    print(f"Saved {len(all_packets)} packets to data/samples/demo_six_threats.pcap")

if __name__ == "__main__":
    main()
