"""
UniShield AI -- Golden Demo PCAP Generator (Phase 11)
=====================================================
Generates a realistic sequence of synthetic network traffic 
for the End-to-End Demo.

Progression:
1. Normal Traffic
2. Port Scan (Recon)
3. DGA-like DNS Queries
4. Periodic TCP Beacons (C2)
5. Encrypted Session Anomaly
6. High Volume Data Burst (Exfiltration)

Output: data/samples/demo_scenario.pcap
"""

from pathlib import Path
import warnings
import logging

warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.all import wrpcap, IP, TCP, UDP, DNS, DNSQR, DNSRR

def generate():
    output_path = Path("data/samples/demo_scenario.pcap")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    packets = []
    base_ts = 1_720_000_000.0
    
    attacker_a = "192.168.1.50" # Recon + C2
    attacker_b = "192.168.1.51" # DGA
    attacker_c = "192.168.1.52" # Encrypted
    attacker_d = "192.168.1.53" # Exfiltration
    
    victim = "10.0.0.10"
    evil_ip = "103.45.67.89"
    dns_server = "8.8.8.8"
    
    # ---------------------------------------------------------
    # 0. Warmup Baseline (so Exfiltration Detector thinks baseline is available)
    # ---------------------------------------------------------
    for port in range(1000, 1060):
        p = IP(src=attacker_d, dst=victim) / TCP(sport=port, dport=80, flags="S")
        p.time = base_ts + (port * 0.001)
        packets.append(p)
        # Send FIN to complete the flow so it's extracted immediately
        p2 = IP(src=attacker_d, dst=victim) / TCP(sport=port, dport=80, flags="FA")
        p2.time = base_ts + (port * 0.001) + 0.001
        packets.append(p2)
    
    # ---------------------------------------------------------
    # 1. Normal Traffic (Web Browsing)
    # ---------------------------------------------------------
    base_ts += 5.0
    for i in range(5):
        p = IP(src=attacker_a, dst="93.184.216.34") / TCP(sport=50000+i, dport=443, flags="S", seq=100)
        p.time = base_ts + i * 2.0
        packets.append(p)
    
    # ---------------------------------------------------------
    # 2. Reconnaissance (Port Scan)
    # ---------------------------------------------------------
    base_ts += 60.0
    for port in range(20, 100):
        p = IP(src=attacker_a, dst=victim) / TCP(sport=51000, dport=port, flags="S", seq=200)
        p.time = base_ts + (port * 0.05)
        packets.append(p)
        
    # ---------------------------------------------------------
    # 3. DGA DNS Queries
    # ---------------------------------------------------------
    base_ts += 60.0
    # Use very random strings for high entropy, and different src ports to make them different flows
    dga_domains = [
        "x1y2z3a4b5c6d7e8f90g1h2i3j4k5l6.com.", 
        "zzqqwwkkmmnnbbvvxxcc.net.", 
        "1234567890abcdefghijklmnopqrstuvwxyz.org."
    ]
    for i, dom in enumerate(dga_domains):
        p = IP(src=attacker_b, dst=dns_server) / UDP(sport=52000+i, dport=53) / DNS(
            id=0x1234+i, qr=0, rd=1, qd=DNSQR(qname=dom, qtype="A")
        )
        p.time = base_ts + (i * 5.0)
        packets.append(p)
        # Do not send response to keep last_dns_event as query
        
    # ---------------------------------------------------------
    # 4. C2 Beaconing (Regular intervals)
    # ---------------------------------------------------------
    base_ts += 60.0
    for i in range(15):
        # Every exactly 10 seconds
        p = IP(src=attacker_a, dst=evil_ip) / TCP(sport=53000, dport=80, flags="PA") / b"BEACON_PAYLOAD_DATA"
        p.time = base_ts + (i * 10.0)
        packets.append(p)
        
    # ---------------------------------------------------------
    # 5. Encrypted Session Anomaly (TLS-like on 443)
    # ---------------------------------------------------------
    base_ts += 160.0
    
    # We need Scapy's TLS module to create a mock TLS Client Hello so PcapReader extracts it
    try:
        from scapy.layers.tls.all import TLS, TLSClientHello, TLS_Ext_ServerName, ServerName
        tls_payload = TLS(msg=[TLSClientHello(ext=[TLS_Ext_ServerName(servernames=[ServerName(servername="malicious-c2.example")])])])
    except ImportError:
        # Fallback to raw hex of a TLS 1.2 ClientHello if scapy TLS is not loaded properly
        tls_payload = bytes.fromhex("160301005a010000560303") + (b"A" * 70)
        
    for i in range(20):
        # Payload size jumps around erratically
        payload_size = 50 if i % 2 == 0 else 1200
        p = IP(src=attacker_c, dst=evil_ip) / TCP(sport=54000, dport=443, flags="PA") / tls_payload / (b"A" * payload_size)
        # Irregular timing, but spread over > 10 seconds
        p.time = base_ts + (i * 1.5)
        packets.append(p)
        
    # ---------------------------------------------------------
    # 6. Exfiltration (Massive Data Transfer)
    # ---------------------------------------------------------
    base_ts += 60.0
    for i in range(1100): # 1100 packets * 50000 bytes = 55 MB
        p = IP(src=attacker_d, dst=evil_ip) / TCP(sport=55000, dport=80, flags="A") / (b"X" * 50000)
        p.time = base_ts + (i * 0.005) # very fast burst
        packets.append(p)
        
    # ---------------------------------------------------------
    # 7. DDoS (Volumetric Anomaly from external IPs)
    # ---------------------------------------------------------
    base_ts += 60.0
    for i in range(300):
        fake_ip = f"203.0.113.{i % 250}"
        p = IP(src=fake_ip, dst=victim) / TCP(sport=10000+(i%1000), dport=80, flags="S")
        p.time = base_ts + (i * 0.001)
        packets.append(p)
        
    wrpcap(str(output_path), packets)
    print(f"[DEMO] Wrote {len(packets)} packets to {output_path}")

if __name__ == "__main__":
    generate()
