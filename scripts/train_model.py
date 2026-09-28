"""
UniShield AI -- Unified Model Training CLI
==========================================
Provides a CLI to train and evaluate ML models for various detectors.
"""

import argparse
import sys
import os

def main():
    parser = argparse.ArgumentParser(description="UniShield AI Model Training CLI")
    parser.add_argument(
        "--detector",
        type=str,
        required=True,
        choices=["dga", "encrypted"],
        help="Which detector to train (dga, encrypted)"
    )
    parser.add_argument(
        "--dataset",
        type=str,
        help="Path to the preprocessed dataset CSV"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Path to save the trained model artifact"
    )

    args = parser.parse_args()

    # Default datasets
    dataset_path = args.dataset
    if not dataset_path:
        if args.detector == "dga":
            dataset_path = "data/processed/dga_dataset.csv"
        elif args.detector == "encrypted":
            dataset_path = "data/processed/encrypted_dataset.csv"

    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        print("Please run the corresponding download script in scripts/datasets/ first.")
        sys.exit(1)

    print(f"[*] Training {args.detector} model using dataset {dataset_path}...")

    if args.detector == "dga":
        from src.models.training.dga_train import SKLEARN_AVAILABLE, load_real_data, train_dga_model
        
        if not SKLEARN_AVAILABLE:
            print("Error: scikit-learn is required.")
            sys.exit(1)
            
        try:
            from sklearn.model_selection import train_test_split
        except ImportError:
            pass
            
        X, y = load_real_data(dataset_path)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        output_path = args.output or "models/trained/dga_random_forest.pkl"
        train_dga_model(X_train, y_train, X_test, y_test, save_path=output_path)

    elif args.detector == "encrypted":
        from src.models.training.encrypted_train import SKLEARN_AVAILABLE, XGB_AVAILABLE, load_real_data, train_encrypted_session_model
        
        X, y, feature_names = load_real_data(dataset_path)
        
        if SKLEARN_AVAILABLE:
            from sklearn.model_selection import train_test_split
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        else:
            split = int(len(X) * 0.8)
            X_train, X_test = X[:split], X[split:]
            y_train, y_test = y[:split], y[split:]
            
        model_type = "xgboost" if XGB_AVAILABLE else "random_forest"
        ext = ".json" if model_type == "xgboost" else ".pkl"
        output_path = args.output or f"models/trained/encrypted_{model_type}{ext}"
        
        train_encrypted_session_model(X_train, y_train, X_test, y_test, feature_names, model_type=model_type, save_path=output_path)
        
    print(f"[+] Successfully trained {args.detector} model.")

if __name__ == "__main__":
    main()
