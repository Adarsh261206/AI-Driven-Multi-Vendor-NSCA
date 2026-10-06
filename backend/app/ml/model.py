"""
ML Model Inference — Loads trained vendor/device_type models

Usage:
  from app.ml.model import get_ml_detector
  detector = get_ml_detector()
  vendor, platform, device_type, confidence, method = detector.predict(content)
"""

import json
from pathlib import Path
from typing import Optional, Tuple

ARTIFACT_DIR = Path(__file__).parent / "model_artifacts"

# Lazy-loaded singletons
_vendor_model = None
_device_model = None
_metadata = None
_normalisation_model = None
_semantic_model = None
_risk_model = None


def _load_models():
    global _vendor_model, _device_model, _metadata, _normalisation_model, _semantic_model, _risk_model
    if _vendor_model is not None and _normalisation_model is not None:
        return
    try:
        import joblib
        if (ARTIFACT_DIR / "vendor_model.joblib").exists():
            _vendor_model = joblib.load(ARTIFACT_DIR / "vendor_model.joblib")
            _device_model = joblib.load(ARTIFACT_DIR / "device_type_model.joblib")
        if (ARTIFACT_DIR / "normalisation_model.joblib").exists():
            _normalisation_model = joblib.load(ARTIFACT_DIR / "normalisation_model.joblib")
        if (ARTIFACT_DIR / "semantic_model.joblib").exists():
            _semantic_model = joblib.load(ARTIFACT_DIR / "semantic_model.joblib")
        if (ARTIFACT_DIR / "risk_model.joblib").exists():
            _risk_model = joblib.load(ARTIFACT_DIR / "risk_model.joblib")
        if (ARTIFACT_DIR / "metadata.json").exists():
            import json as _json
            _metadata = _json.loads((ARTIFACT_DIR / "metadata.json").read_text())
        else:
            _metadata = {}
        # Load per-engine metas for info
        for meta_file in ["normalisation_meta.json", "semantic_meta.json", "risk_meta.json", "all_engines_meta.json"]:
            if (ARTIFACT_DIR / meta_file).exists():
                try:
                    _metadata[meta_file.replace(".json","")] = json.loads((ARTIFACT_DIR / meta_file).read_text())
                except Exception:
                    pass
    except Exception as e:
        print(f"ML model load failed: {e}")
        _vendor_model = None


class MLDetector:
    """ML-based vendor and device type detector."""

    def __init__(self):
        _load_models()
        self.vendor_model = _vendor_model
        self.device_model = _device_model
        self.metadata = _metadata or {}

    @property
    def is_available(self) -> bool:
        return self.vendor_model is not None

    def predict(self, content: str) -> Tuple[str, str, str, float, str]:
        """
        Predict vendor, platform, device_type from config content.

        Returns:
            (vendor, platform, device_type, confidence, method)
            method = "ml" or "fallback"
        """
        if not self.is_available or not content.strip():
            return "unknown", "unknown", "unknown", 0.0, "fallback"

        try:
            # Vendor
            vendor_probs = self.vendor_model.predict_proba([content])[0]
            vendor_pred = self.vendor_model.predict([content])[0]
            vendor_conf = float(max(vendor_probs))

            # Device type
            device_probs = self.device_model.predict_proba([content])[0]
            device_pred = self.device_model.predict([content])[0]
            device_conf = float(max(device_probs))

            # Combined confidence (harmonic mean of vendor and device)
            combined = (2 * vendor_conf * device_conf) / (vendor_conf + device_conf) if (vendor_conf + device_conf) > 0 else vendor_conf

            # Platform from vendor
            platform_map = {
                "cisco": "ios_xe",
                "juniper": "junos",
                "fortinet": "fortios",
                "paloalto": "panos",
            }
            platform = platform_map.get(vendor_pred, "unknown")

            return vendor_pred, platform, device_pred, combined, "ml"

        except Exception as e:
            print(f"ML predict failed: {e}")
            return "unknown", "unknown", "unknown", 0.0, "fallback"

    def get_model_info(self) -> dict:
        """Return model metadata for report."""
        return {
            "available": self.is_available,
            "vendor_classes": self.metadata.get("vendor_classes", []),
            "device_type_classes": self.metadata.get("device_type_classes", []),
            "vendor_accuracy": self.metadata.get("vendor_accuracy", 0),
            "device_type_accuracy": self.metadata.get("device_type_accuracy", 0),
            "model": self.metadata.get("model", "TF-IDF + LogisticRegression"),
            "train_size": self.metadata.get("train_size", 0),
            "method": "ml" if self.is_available else "regex",
        }


# Singleton
_ml_detector: Optional[MLDetector] = None


def get_ml_detector() -> MLDetector:
    global _ml_detector
    if _ml_detector is None:
        _ml_detector = MLDetector()
    return _ml_detector


def get_normalisation_predictor():
    """Return (model, is_available) for normalisation ML."""
    _load_models()
    return _normalisation_model, _normalisation_model is not None


def get_semantic_predictor():
    """Return (model, is_available) for semantic ML."""
    _load_models()
    return _semantic_model, _semantic_model is not None


def get_risk_predictor():
    """Return (model, is_available) for risk scoring ML."""
    _load_models()
    return _risk_model, _risk_model is not None


def get_all_engines_info() -> dict:
    """Return combined info for all 5 ML models."""
    _load_models()
    base = get_ml_detector().get_model_info()
    # Add per-engine metas
    for key in ["normalisation_meta", "semantic_meta", "risk_meta"]:
        if key in (_metadata or {}):
            base[key] = _metadata[key]
    if "all_engines_meta" in (_metadata or {}):
        base["all_engines"] = _metadata["all_engines_meta"]
    base["total_models"] = sum([
        1 if _vendor_model is not None else 0,
        1 if _normalisation_model is not None else 0,
        1 if _semantic_model is not None else 0,
        1 if _risk_model is not None else 0,
    ])
    return base
