"""
UniShield AI -- DGA ML Training & Inference
=================================================
Machine Learning component for DGA Detection using REAL DATA.
"""

import logging
import os
import pickle
import json
import datetime
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from src.features.feature_vector import FeatureVector

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

logger = logging.getLogger(__name__)


# ================================================================
# Inference Component
# ================================================================

class DGARandomForest:
    """Reusable Inference Component for DGA."""
    
    FEATURE_NAMES = [
        "dns_query_length",
        "dns_entropy",
        "dns_ngram_entropy",
        "dns_digit_ratio",
        "dns_unique_char_count",
        "dns_alpha_ratio",
        "dns_hyphen_ratio"
    ]
    
    def __init__(self, cfg: dict = None) -> None:
        self.cfg = cfg or {}
        # Changed default to models/trained/
        self.model_path = self.cfg.get("model_path", "models/trained/dga_random_forest.pkl")
        self.model = None
        self.metadata = None
        
        self._load_model()
                
    def _load_model(self):
        from src.models.registry import registry
        
        path, meta = registry.discover_and_validate("dga", preferred_type="random_forest")
        if not path:
            logger.warning("DGARandomForest failed to load. Will fallback to purely statistical detection.")
            return
            
        self.metadata = meta
        
        if SKLEARN_AVAILABLE:
            try:
                with open(path, "rb") as f:
                    self.model = pickle.load(f)
                logger.info(f"Loaded DGARandomForest from {path}")
            except Exception as e:
                self.model = None
                logger.error(f"Failed to load DGA ML model: {e}")
        else:
            logger.error("scikit-learn is required to load DGARandomForest.")

    def is_ready(self) -> bool:
        return self.model is not None and SKLEARN_AVAILABLE
        
    def _extract_features(self, fv: FeatureVector) -> Optional[np.ndarray]:
        if not fv.get("dns_is_query"):
            return None
            
        vector = []
        for feat in self.FEATURE_NAMES:
            val = fv.get(feat, 0.0)
            if val is None:
                val = 0.0
            vector.append(float(val))
            
        return np.array([vector])

    def score(self, fv: FeatureVector) -> Optional[float]:
        """
        Returns probability of being DGA (Class 1) [0.0 - 1.0].
        Returns None if model not ready or extraction fails.
        """
        if not self.is_ready():
            return None
            
        x = self._extract_features(fv)
        if x is None:
            return None
            
        try:
            probs = self.model.predict_proba(x)
            return float(probs[0][1])
        except Exception as e:
            logger.error(f"DGA ML inference error: {e}")
            return None


# ================================================================
# Training Pipeline
# ================================================================

def load_real_data(csv_path: str) -> Tuple[np.ndarray, np.ndarray]:
    """
    Load real preprocessed DGA dataset.
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at {csv_path}. Run download_dga.py first.")
        
    df = pd.read_csv(csv_path)
    X = df[DGARandomForest.FEATURE_NAMES].values
    y = df["label"].values
    return X, y

def train_dga_model(
    X_train: np.ndarray, 
    y_train: np.ndarray, 
    X_test: np.ndarray, 
    y_test: np.ndarray,
    save_path: str = "models/trained/dga_random_forest.pkl"
) -> Any:
    """
    Train a Random Forest classifier for DGA detection using REAL data.
    """
    if not SKLEARN_AVAILABLE:
        raise ImportError("scikit-learn is required for ML training.")
        
    print(f"Training DGA Random Forest on {len(X_train)} samples...")
    
    clf = RandomForestClassifier(
        n_estimators=100, 
        max_depth=12, 
        random_state=42, 
        class_weight="balanced"
    )
    
    clf.fit(X_train, y_train)
    
    print("Evaluating on test set...")
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    
    print("\nClassification Report:")
    report = classification_report(y_test, y_pred, output_dict=True)
    print(classification_report(y_test, y_pred))
    
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    auc = roc_auc_score(y_test, y_prob)
    print(f"ROC-AUC: {auc:.4f}")
    
    # Expose feature importances
    importances = clf.feature_importances_
    print("\nFeature Importances:")
    for name, imp in zip(DGARandomForest.FEATURE_NAMES, importances):
        print(f"  {name}: {imp:.4f}")
        
    # Save
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    with open(save_path, "wb") as f:
        pickle.dump(clf, f)
        
    print(f"\nModel saved to {save_path}")
    
    # Save metadata
    metadata = {
        "model_name": "DGARandomForest",
        "model_version": "v1.0.0",
        "feature_schema_version": "v1",
        "training_dataset": "MajesticMillion + 360Netlab (Real Data)",
        "features": DGARandomForest.FEATURE_NAMES,
        "training_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "random_seed": 42,
        "algorithm": "RandomForestClassifier",
        "metrics": {
            "precision": report["1"]["precision"],
            "recall": report["1"]["recall"],
            "f1": report["1"]["f1-score"],
            "roc_auc": auc
        }
    }
    
    meta_path = save_path.replace(".pkl", ".json")
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=4)
        
    print(f"Metadata saved to {meta_path}")
    
    return clf


if __name__ == "__main__":
    if not SKLEARN_AVAILABLE:
        print("scikit-learn not installed. Cannot run training.")
        exit(1)
        
    print("=" * 60)
    print("UniShield AI -- DGA Training Pipeline (Phase 17)")
    print("=" * 60)
    
    try:
        X, y = load_real_data("data/processed/dga_dataset.csv")
        print(f"Loaded dataset: {X.shape[0]} samples, {X.shape[1]} features.")
        
        # Split (stratified)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        train_dga_model(X_train, y_train, X_test, y_test)
    except Exception as e:
        print(f"Error during training: {e}")
