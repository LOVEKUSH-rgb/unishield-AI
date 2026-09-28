"""
UniShield AI -- Encrypted Session ML Training & Inference
=========================================================
Machine Learning component for detecting anomalous
behavior inside encrypted TLS/QUIC sessions using ONLY
passively observed metadata and SPLT (Sequence of Packet
Lengths and Times).

CRITICAL: Never feed payload content into this model.
"""

import logging
import os
import pickle
import json
import datetime
import numpy as np
import pandas as pd
from typing import Any, Dict, List, Optional, Tuple

from src.features.feature_vector import FeatureVector

try:
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False

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

class EncryptedSessionModel:
    """Reusable Inference Component for Encrypted Session Detection."""
    
    # Core statistical features (12 features)
    STAT_FEATURES = [
        "packet_count",
        "byte_count",
        "pkt_size_mean",
        "pkt_size_std",
        "pkt_size_cv",
        "iat_mean",
        "iat_cv",
        "flow_duration",
        "tls_version_known",
        "tls_has_sni",
        "tls_has_ja3",
        "tls_resumed"
    ]
    
    def __init__(self, cfg: dict = None) -> None:
        self.cfg = cfg or {}
        
        # SPLT configuration
        self.splt_max_seq = int(self.cfg.get("splt_max_sequence_length", 20))
        
        # Model loading (updated path to trained/)
        self.xgb_path = self.cfg.get("ml", {}).get("model_path", "models/trained/encrypted_xgboost.json")
        self.rf_path = self.cfg.get("ml", {}).get("rf_fallback_path", "models/trained/encrypted_rf.pkl")
        
        self.model = None
        self.model_type = None
        self.metadata = None
        
        self._load_model()
        
    def _load_model(self) -> None:
        from src.models.registry import registry
        
        path, meta = registry.discover_and_validate("encrypted", preferred_type="xgboost")
        if not path:
            logger.warning("EncryptedSessionModel failed to load. Will fallback to purely statistical detection.")
            return
            
        self.metadata = meta
        self.model_type = registry.active_models["encrypted"]["type"]
        
        try:
            if self.model_type == "xgboost" and XGB_AVAILABLE:
                self.model = xgb.XGBClassifier()
                self.model.load_model(path)
                logger.info(f"Loaded XGBoost from {path}")
            elif self.model_type == "random_forest" and SKLEARN_AVAILABLE:
                with open(path, "rb") as f:
                    self.model = pickle.load(f)
                logger.info(f"Loaded Random Forest fallback from {path}")
            else:
                self.model = None
                logger.error(f"Library not available for model type {self.model_type}")
        except Exception as e:
            self.model = None
            logger.error(f"EncryptedSessionModel artifact load failed: {e}")

    def is_ready(self) -> bool:
        return self.model is not None
        
    def _extract_features(self, fv: FeatureVector) -> Optional[np.ndarray]:
        """
        Extracts stats and SPLT into a flat numpy array.
        Length: len(STAT_FEATURES) + (2 * splt_max_seq)
        """
        if not fv.has_group("tls"):
            # If no TLS features were even attempted to be extracted, we skip
            return None
            
        vector = []
        
        # 1. Statistical features
        for feat in self.STAT_FEATURES:
            val = fv.get(feat, 0.0)
            if val is None:
                val = 0.0
            vector.append(float(val))
            
        # 2. SPLT Sizes
        sizes = fv.get("splt_sizes") or []
        for i in range(self.splt_max_seq):
            if i < len(sizes):
                vector.append(float(sizes[i]))
            else:
                vector.append(0.0)
                
        # 3. SPLT Times
        times = fv.get("splt_times") or []
        for i in range(self.splt_max_seq):
            if i < len(times):
                vector.append(float(times[i]))
            else:
                vector.append(0.0)
                
        return np.array([vector])

    def score(self, fv: FeatureVector) -> Optional[float]:
        """
        Returns probability of being suspicious (Class 1) [0.0 - 1.0].
        Returns None if model not ready or extraction fails.
        """
        if not self.is_ready():
            return None
            
        x = self._extract_features(fv)
        if x is None:
            return None
            
        try:
            if self.model_type == "xgboost":
                # XGBoost predict_proba
                probs = self.model.predict_proba(x)
                return float(probs[0][1])
            elif self.model_type == "random_forest":
                probs = self.model.predict_proba(x)
                return float(probs[0][1])
        except Exception as e:
            logger.error(f"Encrypted session inference error: {e}")
            return None


# ================================================================
# Training Pipeline
# ================================================================

def load_real_data(csv_path: str, splt_len: int = 20) -> Tuple[np.ndarray, np.ndarray]:
    """
    Load real preprocessed Encrypted Session dataset (CIC-IDS2017 derived).
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at {csv_path}. Run download_encrypted.py first.")
        
    df = pd.read_csv(csv_path)
    
    # We dynamically build the exact feature schema required by the model
    feature_names = EncryptedSessionModel.STAT_FEATURES.copy()
    for i in range(splt_len):
        feature_names.append(f"splt_size_{i}")
    for i in range(splt_len):
        feature_names.append(f"splt_time_{i}")
        
    # We know standard CIC-IDS2017 doesn't have SPLT arrays natively, so if they are missing from df, add zeros
    for f in feature_names:
        if f not in df.columns:
            df[f] = 0.0
            
    X = df[feature_names].values
    y = df["label"].values
    return X, y, feature_names


def train_encrypted_session_model(
    X_train: np.ndarray, 
    y_train: np.ndarray, 
    X_test: np.ndarray, 
    y_test: np.ndarray,
    feature_names: List[str],
    splt_len: int = 20,
    model_type: str = "xgboost",
    save_path: str = "models/trained/encrypted_xgboost.pkl"
) -> Any:
    """
    Train an encrypted session classifier on real data.
    """
    if model_type == "xgboost" and not XGB_AVAILABLE:
        print("XGBoost not available, falling back to Random Forest.")
        model_type = "random_forest"
        save_path = save_path.replace("xgboost", "rf").replace(".json", ".pkl")
        
    print(f"Training {model_type} on {len(X_train)} samples...")
    
    if model_type == "xgboost":
        clf = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            scale_pos_weight=(len(y_train) - sum(y_train)) / max(1, sum(y_train)),
            random_state=42,
            use_label_encoder=False,
            eval_metric='logloss'
        )
    else:
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is required for ML training.")
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
    
    auc = 0.0
    report = None
    if SKLEARN_AVAILABLE:
        print("\nClassification Report:")
        report = classification_report(y_test, y_pred, output_dict=True)
        print(classification_report(y_test, y_pred))
        
        print("Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        
        try:
            auc = roc_auc_score(y_test, y_prob)
            print(f"\nROC-AUC Score: {auc:.4f}")
        except Exception:
            pass
            
    # Feature Importances mapping
    try:
        importances = clf.feature_importances_
        print("\nTop 10 Feature Importances:")
        indices = np.argsort(importances)[::-1]
        for idx in indices[:10]:
            print(f"  {feature_names[idx]}: {importances[idx]:.4f}")
    except Exception as e:
        print(f"Could not extract feature importances: {e}")
        
    # Save
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    if model_type == "xgboost":
        # Force JSON extension for xgboost 
        if save_path.endswith(".pkl"):
            save_path = save_path.replace(".pkl", ".json")
        clf.save_model(save_path)
    else:
        with open(save_path, "wb") as f:
            pickle.dump(clf, f)
        
    print(f"\nModel saved to {save_path}")
    
    # Save Metadata
    metadata = {
        "model_name": f"EncryptedSession_{model_type}",
        "model_version": "v1.0.0",
        "feature_schema_version": "v1",
        "training_dataset": "CIC-IDS2017 Sample (Real Data)",
        "features": feature_names,
        "training_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "random_seed": 42,
        "algorithm": model_type,
        "metrics": {
            "precision": report["1"]["precision"] if report else 0.0,
            "recall": report["1"]["recall"] if report else 0.0,
            "f1": report["1"]["f1-score"] if report else 0.0,
            "roc_auc": auc
        }
    }
    
    if model_type == "xgboost":
        meta_path = save_path.replace(".json", "_meta.json")
    else:
        meta_path = save_path.replace(".pkl", ".json")
        
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=4)
        
    print(f"Metadata saved to {meta_path}")
    
    return clf


if __name__ == "__main__":
    if not SKLEARN_AVAILABLE:
        print("scikit-learn not installed. Cannot run evaluation metrics.")
        
    print("=" * 60)
    print("UniShield AI -- Encrypted Session ML Pipeline (Phase 17)")
    print("=" * 60)
    
    try:
        X, y, feature_names = load_real_data("data/processed/encrypted_dataset.csv")
        print(f"Loaded dataset: {X.shape[0]} samples, {X.shape[1]} features.")
        
        if SKLEARN_AVAILABLE:
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        else:
            split = int(len(X) * 0.8)
            X_train, X_test = X[:split], X[split:]
            y_train, y_test = y[:split], y[split:]
        
        # Train XGBoost
        if XGB_AVAILABLE:
            train_encrypted_session_model(X_train, y_train, X_test, y_test, feature_names, model_type="xgboost", save_path="models/trained/encrypted_xgboost.json")
        elif SKLEARN_AVAILABLE:
            train_encrypted_session_model(X_train, y_train, X_test, y_test, feature_names, model_type="random_forest", save_path="models/trained/encrypted_rf.pkl")
        else:
            print("Neither XGBoost nor Scikit-Learn is installed. Cannot train.")
            
    except Exception as e:
        print(f"Error during training: {e}")
