"""Inference pipeline and predictor class for the Hybrid QNN model."""

from __future__ import annotations

import logging
import os
import pickle
from typing import Any

import numpy as np
import pandas as pd
import torch

from qnn.model import HybridQNN
from qnn.preprocessing import KDDPreprocessor, NSL_KDD_COLUMNS

logger = logging.getLogger("netsentinel.qnn.predict")


class QNNPredictor:
    """Predictor class responsible for loading checkpoints and performing inference."""

    def __init__(
        self,
        model_path: str = "instance/qnn_model.pth",
        preprocessor_path: str = "instance/qnn_preprocessor.pkl",
    ) -> None:
        """Initialize the QNN Predictor.

        Args:
            model_path: Path to the trained PyTorch checkpoint.
            preprocessor_path: Path to the serialized scikit-learn preprocessor.
        """
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model checkpoint not found at: {model_path}")
        if not os.path.exists(preprocessor_path):
            raise FileNotFoundError(f"Preprocessor file not found at: {preprocessor_path}")

        # 1. Load preprocessor
        with open(preprocessor_path, "rb") as f:
            self.preprocessor: KDDPreprocessor = pickle.load(f)

        # 2. Load model metadata and weights
        checkpoint = torch.load(model_path, map_location=self.device)
        input_dim = checkpoint["input_dim"]
        num_qubits = checkpoint.get("num_qubits", 4)
        num_layers = checkpoint.get("num_layers", 2)

        # 3. Instantiate and configure model
        self.model = HybridQNN(input_dim=input_dim, num_qubits=num_qubits, num_layers=num_layers)
        self.model.load_state_dict(checkpoint["state_dict"])
        self.model.to(self.device)
        self.model.eval()

        logger.info("QNNPredictor initialized successfully on device: %s", self.device)

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        """Run inference on a raw dataframe and return class predictions (0=Normal, 1=Anomaly)."""
        X, _ = self.preprocessor.transform(df)
        X_tensor = torch.tensor(X, dtype=torch.float32, device=self.device)

        with torch.inference_mode():
            probs = self.model(X_tensor)
            predictions = (probs >= 0.5).int().cpu().numpy().flatten()

        return predictions

    def predict_probabilities(self, df: pd.DataFrame) -> np.ndarray:
        """Run inference and return class probabilities.

        Returns:
            NumPy array of shape (num_samples, 2) where column 0 is Normal and
            column 1 is Anomaly.
        """
        X, _ = self.preprocessor.transform(df)
        X_tensor = torch.tensor(X, dtype=torch.float32, device=self.device)

        with torch.inference_mode():
            probs = self.model(X_tensor).cpu().numpy()
            # Convert single probabilities into [Normal, Anomaly] class probabilities
            binary_probs = np.hstack([1.0 - probs, probs])

        return binary_probs

    def predict_structured(self, df: pd.DataFrame) -> list[dict[str, Any]]:
        """Run batch inference and return detailed structured predictions.

        Optimized using PyTorch inference mode.

        Args:
            df: Raw input feature dataframe.

        Returns:
            A list of dictionaries, one per input sample, containing:
              - 'attack_type': "Generic Attack" or "Normal"
              - 'probability': Anomaly probability score in [0.0, 1.0]
              - 'confidence': Model confidence level in range [0.5, 1.0]
              - 'prediction_label': "Intrusion" or "Normal"
        """
        X, _ = self.preprocessor.transform(df)
        X_tensor = torch.tensor(X, dtype=torch.float32, device=self.device)

        results = []
        with torch.inference_mode():
            probs = self.model(X_tensor).cpu().numpy().flatten()

        for prob in probs:
            is_anomaly = prob >= 0.5
            confidence = float(prob if is_anomaly else (1.0 - prob))

            results.append({
                "attack_type": "Generic Attack" if is_anomaly else "Normal",
                "probability": float(prob),
                "confidence": confidence,
                "prediction_label": "Intrusion" if is_anomaly else "Normal",
            })

        return results


def map_features_to_df(payload: Any) -> pd.DataFrame:
    """Unify mapping of various feature inputs to the standard 42-column NSL-KDD DataFrame structure.

    Args:
        payload: Can be a single flat list/dictionary/object, or a batch list of lists/dicts/objects.

    Returns:
        A pandas DataFrame containing standardized 42-column NSL-KDD records.
    """
    # 1. Normalize payload into a list of items
    if isinstance(payload, list):
        if not payload:
            return pd.DataFrame(columns=NSL_KDD_COLUMNS[:-1])
        # Check if it's a flat list of primitive values (single sample representation)
        if not isinstance(payload[0], (list, dict)) and not hasattr(payload[0], "__dict__") and not isinstance(payload[0], dict):
            items = [payload]
        else:
            items = payload
    else:
        items = [payload]

    records = []
    for item in items:
        # Build default record
        row_data = {col: 0.0 for col in NSL_KDD_COLUMNS[:-1]}

        # Case A: Input item is a list/tuple of raw numbers
        if isinstance(item, (list, tuple)):
            if len(item) == 5:
                row_data["duration"] = float(item[0])
                row_data["src_bytes"] = int(item[1])
                row_data["dst_bytes"] = int(item[2])
                row_data["count"] = int(item[3])
                row_data["srv_count"] = int(item[4])
            elif len(item) >= 41:
                # Direct full columns map
                for idx, col in enumerate(NSL_KDD_COLUMNS[:-1][:len(item)]):
                    row_data[col] = item[idx]
            else:
                raise ValueError(f"Expected 5 or 41 features. Got {len(item)}.")

        # Case B: Input item is a dictionary or custom object
        else:
            def get_val(key: str) -> float:
                if isinstance(item, dict):
                    return float(item.get(key, 0.0))
                return float(getattr(item, key, 0.0))

            # Check if dict/object represents psutil counters or vital features
            if isinstance(item, dict) and "bytes_sent" in item or hasattr(item, "bytes_sent"):
                row_data["src_bytes"] = get_val("bytes_sent")
                row_data["dst_bytes"] = get_val("bytes_received")
                row_data["count"] = get_val("packets_sent")
                row_data["srv_count"] = get_val("packets_received")
            else:
                row_data["duration"] = get_val("duration")
                row_data["src_bytes"] = get_val("src_bytes")
                row_data["dst_bytes"] = get_val("dst_bytes")
                row_data["count"] = get_val("count")
                row_data["srv_count"] = get_val("srv_count")

        # Set discrete categorical fields and label to standard defaults
        row_data["protocol_type"] = "tcp"
        row_data["service"] = "private"
        row_data["flag"] = "SF"
        row_data["label"] = "normal"

        records.append(row_data)

    return pd.DataFrame(records)


def snapshot_to_kdd_df(snapshot: dict[str, Any] | Any) -> pd.DataFrame:
    """Map real-time network monitor metrics to a standard NSL-KDD row format.

    Args:
        snapshot: A dictionary or a NetworkMonitorSnapshot object containing
                  keys/attributes such as bytes_sent, bytes_received,
                  packets_sent, packets_received, upload_speed, download_speed.

    Returns:
        A pandas DataFrame of shape (1, 42) representing a single KDD connection record.
    """
    return map_features_to_df(snapshot)

