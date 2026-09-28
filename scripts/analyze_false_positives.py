"""
UniShield AI -- False Positive Analysis
=======================================
Analyzes false positive rates for active models and generates
insights into threshold adjustments.
"""

import os
import json
from collections import Counter
from src.models.registry import registry
from src.utils.logging import get_logger

logger = get_logger(__name__)

def analyze_false_positives():
    print("=" * 60)
    print("UniShield AI -- False Positive Analysis Tool")
    print("=" * 60)
    
    # 1. Load active models
    active_models = {}
    
    dga_path, dga_meta = registry.discover_and_validate("dga", preferred_type="random_forest")
    if dga_meta:
        active_models["DGA"] = dga_meta
        
    enc_path, enc_meta = registry.discover_and_validate("encrypted", preferred_type="xgboost")
    if enc_meta:
        active_models["Encrypted"] = enc_meta
        
    if not active_models:
        print("No active models found in registry. Exiting.")
        return
        
    for name, meta in active_models.items():
        print(f"\nAnalyzing Model: {name}")
        print(f"Version: {meta.get('model_version', 'unknown')}")
        print("-" * 40)
        
        metrics = meta.get("metrics", {})
        if not metrics:
            print("No metrics available for this model.")
            continue
            
        precision = metrics.get("precision", 0)
        recall = metrics.get("recall", 0)
        
        # Approximate FPR from precision (FP = TP / Precision - TP)
        # But usually we need the confusion matrix. If not available, we use precision.
        print(f"Validation Precision: {precision:.4f}")
        print(f"Validation Recall:    {recall:.4f}")
        print(f"Validation F1 Score:  {metrics.get('f1', 0):.4f}")
        
        # False Positive Insight
        if precision > 0:
            fp_ratio = 1.0 - precision
            print(f"False Positive Ratio (1 - Precision): {fp_ratio*100:.2f}%")
            if fp_ratio > 0.15:
                print("WARNING: Model exhibits > 15% false positive ratio on validation set.")
                print("RECOMMENDATION: Increase `min_confidence_to_alert` in thresholds.yaml.")
            else:
                print("STATUS: False positive ratio is within acceptable limits (< 15%).")
        else:
            print("STATUS: Precision is 0, model is likely untrained or corrupted.")
            
    print("\nTo perform a live false positive analysis, run this script against a live PCAP with known benign traffic.")

if __name__ == "__main__":
    analyze_false_positives()
