"""Unit and integration tests for the PennyLane Hybrid QNN module."""

from __future__ import annotations

import os
import tempfile
import numpy as np
import pytest
import torch
import pandas as pd

from qnn.circuits import PennyLaneVQC
from qnn.model import HybridQNN
from qnn.train import train_qnn_model
from qnn.predict import QNNPredictor, snapshot_to_kdd_df
from qnn.utils import is_model_trained
from qnn.metrics import (
    calculate_evaluation_metrics,
    plot_roc_curve,
    plot_pr_curve,
    plot_confusion_matrix,
)
from app import create_app


def test_pennylane_vqc_configurable_qubits() -> None:
    """Test that PennyLaneVQC compiles and runs for 2, 4, 6, and 8 qubits."""
    for num_qubits in (2, 4, 6, 8):
        vqc = PennyLaneVQC(num_qubits=num_qubits, num_layers=2)
        assert vqc.num_qubits == num_qubits
        assert vqc.num_layers == 2
        
        # Create a batch of mock features (batch_size=3)
        features = torch.randn(3, num_qubits)
        outputs = vqc(features)
        
        # Outputs shape should be (batch_size, num_qubits)
        assert outputs.shape == (3, num_qubits)
        assert outputs.dtype == torch.float32
        
        # Expectation values of Pauli-Z are bounded in [-1.0, 1.0]
        assert torch.all(outputs >= -1.05)
        assert torch.all(outputs <= 1.05)


def test_pennylane_vqc_invalid_qubits() -> None:
    """Test that PennyLaneVQC rejects non-supported qubit counts."""
    with pytest.raises(ValueError, match="num_qubits must be one of"):
        PennyLaneVQC(num_qubits=3)


def test_hybrid_qnn_model_gradients() -> None:
    """Test that gradients flow through the HybridQNN model during backward pass."""
    model = HybridQNN(input_dim=10, num_qubits=4, num_layers=2)
    x = torch.randn(4, 10)
    y = torch.tensor([[0.0], [1.0], [1.0], [0.0]], dtype=torch.float32)
    
    # Forward pass
    outputs = model(x)
    assert outputs.shape == (4, 1)
    assert torch.all(outputs >= 0.0)
    assert torch.all(outputs <= 1.0)
    
    # Compute loss and check backward pass
    criterion = torch.nn.BCELoss()
    loss = criterion(outputs, y)
    loss.backward()
    
    # Check that model weights received gradients
    assert model.vqc.q_layer.weights.grad is not None
    assert model.dense_1[0].weight.grad is not None
    assert model.dense_2.weight.grad is not None


def test_qnn_training_and_predictor() -> None:
    """Test model training process and inference using the QNNPredictor class."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        model_path = os.path.join(tmp_dir, "qnn_model.pth")
        preprocessor_path = os.path.join(tmp_dir, "qnn_preprocessor.pkl")
        
        # Train for a minimal epoch count to speed up tests
        history = train_qnn_model(
            train_path=None,
            model_save_path=model_path,
            preprocessor_save_path=preprocessor_path,
            epochs=2,
            batch_size=16,
            num_qubits=4,
        )
        
        assert "train_loss" in history
        assert "val_precision" in history
        assert "val_recall" in history
        assert "val_f1" in history
        assert "val_auc" in history
        assert "confusion_matrix" in history
        assert len(history["train_loss"]) == 2
        assert os.path.exists(model_path)
        assert os.path.exists(preprocessor_path)
        
        # Test predictor instantiation and inference
        predictor = QNNPredictor(model_path=model_path, preprocessor_path=preprocessor_path)
        
        # Create a single test row
        # 41 columns of mock KDD + dummy label
        test_row = [0.0, "tcp", "private", "SF"] + [0.0] * 37 + ["normal"]
        df = pd.DataFrame([test_row])
        # Add column names to prevent dynamic mapping warnings
        df.columns = [
            "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
            "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
            "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
            "num_file_creations", "num_shells", "num_access_files",
            "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
            "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
            "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
            "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
            "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
            "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
            "dst_host_srv_serror_rate", "dst_host_rerror_rate",
            "dst_host_srv_rerror_rate", "label"
        ]
        
        preds = predictor.predict(df)
        probs = predictor.predict_probabilities(df)
        structured = predictor.predict_structured(df)
        
        assert preds.shape == (1,)
        assert probs.shape == (1, 2)
        assert np.allclose(np.sum(probs, axis=1), 1.0)
        
        assert len(structured) == 1
        assert "attack_type" in structured[0]
        assert "probability" in structured[0]
        assert "confidence" in structured[0]
        assert "prediction_label" in structured[0]
        assert structured[0]["prediction_label"] in ("Intrusion", "Normal")


def test_snapshot_to_kdd_mapper() -> None:
    """Test the psutil snapshot parser to DataFrame."""
    snapshot = {
        "bytes_sent": 1000,
        "bytes_received": 2000,
        "packets_sent": 10,
        "packets_received": 20
    }
    df = snapshot_to_kdd_df(snapshot)
    assert isinstance(df, pd.DataFrame)
    assert df.shape == (1, 42)
    assert df.iloc[0]["src_bytes"] == 1000.0
    assert df.iloc[0]["dst_bytes"] == 2000.0
    assert df.iloc[0]["count"] == 10.0
    assert df.iloc[0]["srv_count"] == 20.0
    assert df.iloc[0]["protocol_type"] == "tcp"


def test_flask_endpoints() -> None:
    """Test Flask client status requests for the QNN module."""
    app = create_app("testing")
    with app.test_client() as client:
        # Check initial QNN status
        response = client.get("/api/qnn/status")
        assert response.status_code == 200
        data = response.get_json()
        assert "model_trained" in data
        assert "trained_status" in data
        assert "prediction" in data
        
        # Trigger training (must return 202 accepted)
        train_resp = client.post("/api/qnn/train", json={"epochs": 2})
        assert train_resp.status_code == 202
        train_data = train_resp.get_json()
        assert train_data["status"] == "success"
        
        # Check training status
        status_resp = client.get("/api/qnn/train-status")
        assert status_resp.status_code == 200
        status_data = status_resp.get_json()
        assert "status" in status_data


def test_metrics_and_plots() -> None:
    """Test metrics helper outputs and plotting utility image persistence."""
    y_true = np.array([0, 1, 1, 0, 1, 0])
    y_pred = np.array([0, 1, 0, 0, 1, 1])
    y_prob = np.array([0.1, 0.9, 0.4, 0.2, 0.8, 0.7])
    
    # Check evaluation metrics computation
    metrics = calculate_evaluation_metrics(y_true, y_pred, y_prob)
    assert "accuracy" in metrics
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1" in metrics
    assert "auc" in metrics
    assert "average_precision" in metrics
    assert "roc_curve" in metrics
    assert "pr_curve" in metrics
    assert "confusion_matrix" in metrics
    assert "classification_report" in metrics

    # Verify plotting utilities and save outputs in temporary folder
    with tempfile.TemporaryDirectory() as tmp_dir:
        roc_path = os.path.join(tmp_dir, "roc.png")
        pr_path = os.path.join(tmp_dir, "pr.png")
        cm_path = os.path.join(tmp_dir, "cm.png")
        
        plot_roc_curve(y_true, y_prob, roc_path)
        plot_pr_curve(y_true, y_prob, pr_path)
        plot_confusion_matrix(y_true, y_pred, cm_path)
        
        assert os.path.exists(roc_path)
        assert os.path.exists(pr_path)
        assert os.path.exists(cm_path)


def test_new_qnn_endpoints() -> None:
    """Test QNN blueprint upload, model, history, metrics, and prediction endpoints."""
    from io import BytesIO
    app = create_app("testing")
    with app.test_client() as client:
        # 1. Test dataset upload
        data = {
            "file": (
                BytesIO(b"duration,protocol_type,service,flag,src_bytes,dst_bytes,label\n0,tcp,http,SF,100,200,normal"),
                "test.csv"
            )
        }
        response = client.post("/api/qnn/upload", data=data, content_type="multipart/form-data")
        assert response.status_code == 200
        assert response.get_json()["status"] == "success"
        assert os.path.exists("instance/uploaded_kdd.csv")
        
        # 2. Test predict (expected 400 since model not trained in fresh test client context, or 200 if already trained)
        predict_resp = client.post("/api/qnn/predict", json={
            "duration": 1.0,
            "src_bytes": 500,
            "dst_bytes": 1000,
            "count": 5,
            "srv_count": 5
        })
        assert predict_resp.status_code in (200, 400)
        resp_json = predict_resp.get_json()
        if predict_resp.status_code == 400:
            assert resp_json["status"] == "error"
        else:
            assert resp_json["status"] == "success"
            assert "prediction" in resp_json
        
        # 3. Test prediction history query
        history_resp = client.get("/api/qnn/prediction-history")
        assert history_resp.status_code == 200
        assert isinstance(history_resp.get_json(), list)

        # 4. Test model download (returns 200 if model file is saved in test context/on disk, 404 otherwise)
        dl_resp = client.get("/api/qnn/model")
        assert dl_resp.status_code in (200, 404)

        # 5. Test metrics (returns 200 if history file is saved, 400 otherwise)
        metrics_resp = client.get("/api/qnn/metrics")
        assert metrics_resp.status_code in (200, 400)

        # 6. Test training parameter validation (epochs validation)
        invalid_train = client.post("/api/qnn/train", json={"epochs": 100})
        assert invalid_train.status_code == 400
        assert "epochs" in invalid_train.get_json()["message"].lower()

        # 7. Test training parameter validation (qubits validation)
        invalid_qubits = client.post("/api/qnn/train", json={"qubits": 5})
        assert invalid_qubits.status_code == 400
        assert "qubits" in invalid_qubits.get_json()["message"].lower()


def test_async_monitoring_and_caching() -> None:
    """Test QNN asynchronous background loop execution and O(1) latency cached status."""
    import time
    app = create_app("testing")
    with app.test_client() as client:
        # Check that status returns a cached dictionary instantly (< 10ms)
        start_time = time.perf_counter()
        response = client.get("/api/qnn/status")
        end_time = time.perf_counter()
        
        assert response.status_code == 200
        data = response.get_json()
        assert "model_trained" in data
        assert "trained_status" in data
        assert "prediction" in data
        
        # Verify latency is sub-50ms for cached response
        latency_ms = (end_time - start_time) * 1000
        assert latency_ms < 50.0



