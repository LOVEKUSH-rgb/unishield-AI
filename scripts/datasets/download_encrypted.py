"""
UniShield AI -- Dataset Acquisition
===================================
Fetches a sample of the CIC-IDS2017 flow dataset for Encrypted Session ML Training.

Source:
CIC-IDS2017 (Canadian Institute for Cybersecurity)
Hosted on GitHub for automated pipeline testing.
"""

import os
import urllib.request
import pandas as pd
import numpy as np
import ssl

ssl._create_default_https_context = ssl._create_unverified_context

def main():
    print("=" * 60)
    print("UniShield AI: Encrypted Session Dataset Engineering")
    print("=" * 60)
    
    os.makedirs("data/raw", exist_ok=True)
    os.makedirs("data/processed", exist_ok=True)
    
    # Using a known small sample of CIC-IDS2017 flow data from a public repo
    csv_url = "https://raw.githubusercontent.com/Western-OC2-Lab/Intrusion-Detection-System-Using-Machine-Learning/main/data/CICIDS2017_sample.csv"
    raw_path = "data/raw/CICIDS2017_sample.csv"
    
    print(f"[+] Downloading dataset from {csv_url} ...")
    try:
        urllib.request.urlretrieve(csv_url, raw_path)
    except Exception as e:
        print(f"Failed to download dataset: {e}")
        return
        
    print(f"[+] Download complete. Loading {raw_path}...")
    df = pd.read_csv(raw_path, skipinitialspace=True)
    
    # Clean column names (CIC-IDS2017 has weird spacing)
    df.columns = [c.strip() for c in df.columns]
    
    print(f"[*] Loaded {len(df)} rows.")
    
    # Map to UniShield features
    # UniShield Features for EncryptedSession:
    # "packet_count", "byte_count", "pkt_size_mean", "pkt_size_std", "pkt_size_cv",
    # "iat_mean", "iat_cv", "flow_duration", "tls_version_known", "tls_has_sni", "tls_has_ja3", "tls_resumed"
    # + SPLT sizes and times (which are NOT in standard CIC-IDS2017)
    
    print("[+] Mapping features to canonical FeatureVector...")
    
    records = []
    
    for idx, row in df.iterrows():
        try:
            # Safe parsing
            pkts = float(row.get('Total Fwd Packets', 0)) + float(row.get('Total Backward Packets', 0))
            bytes_total = float(row.get('Total Length of Fwd Packets', 0)) + float(row.get('Total Length of Bwd Packets', 0))
            dur = float(row.get('Flow Duration', 0)) / 1e6 # microseconds to seconds
            
            pkt_mean = float(row.get('Packet Length Mean', 0))
            pkt_std = float(row.get('Packet Length Std', 0))
            pkt_cv = pkt_std / max(1.0, pkt_mean)
            
            iat_mean = float(row.get('Flow IAT Mean', 0)) / 1e6
            iat_std = float(row.get('Flow IAT Std', 0)) / 1e6
            iat_cv = iat_std / max(0.0001, iat_mean)
            
            # Label parsing (1 for Attack, 0 for BENIGN)
            label_str = str(row.get('Label', 'BENIGN')).upper()
            is_attack = 1 if label_str != 'BENIGN' else 0
            
            # Since CICIDS2017 lacks SPLT arrays and TLS metadata, we set them to 0.
            # This will be reported as a dataset limitation in Phase 17.
            
            record = {
                "packet_count": pkts,
                "byte_count": bytes_total,
                "pkt_size_mean": pkt_mean,
                "pkt_size_std": pkt_std,
                "pkt_size_cv": pkt_cv,
                "iat_mean": iat_mean,
                "iat_cv": iat_cv,
                "flow_duration": dur,
                "tls_version_known": 0.0,
                "tls_has_sni": 0.0,
                "tls_has_ja3": 0.0,
                "tls_resumed": 0.0,
                "label": is_attack
            }
            records.append(record)
        except Exception as e:
            # Skip unparseable rows (NaNs etc)
            continue
            
    out_df = pd.DataFrame(records)
    
    # Handle NaNs and infinite values
    out_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    out_df.dropna(inplace=True)
    
    out_path = "data/processed/encrypted_dataset.csv"
    out_df.to_csv(out_path, index=False)
    
    print(f"[+] Successfully engineered dataset: {out_path}")
    print(out_df["label"].value_counts())
    print("=" * 60)

if __name__ == "__main__":
    main()
