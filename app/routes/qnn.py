"""Flask blueprint and routes for the QNN Intrusion Detection System."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any

from flask import Blueprint, jsonify, request, send_file

from app.extensions import db
from app.models import QNNPredictionHistory
from app.services import NetworkMonitorService

qnn_bp = Blueprint("qnn", __name__, url_prefix="/api/qnn")
logger = logging.getLogger("netsentinel.qnn_routes")
network_monitor_service = NetworkMonitorService()

# In-memory training status cache
_qnn_training_status = {
    "status": "idle",
    "epoch": 0,
    "total_epochs": 0,
    "loss": 0.0,
    "val_loss": 0.0,
}
_qnn_training_lock = threading.Lock()
_cached_qnn_predictor = None

# Thread-safe prediction results cache
_cache_lock = threading.Lock()
_last_prediction_cache = {
    "model_trained": False,
    "trained_status": "Not Trained",
    "anomaly_score": 0.0,
    "prediction": "Normal",
    "prediction_badge_color": "success",
}


def _get_qnn_predictor() -> Any:
    """Helper to fetch and cache the QNN Predictor instance using lazy imports."""
    global _cached_qnn_predictor
    if _cached_qnn_predictor is None:
        try:
            from qnn.utils import is_model_trained
            from qnn.predict import QNNPredictor

            if is_model_trained():
                _cached_qnn_predictor = QNNPredictor()
        except Exception:
            logger.exception("Failed to load QNN model into cache")
            _cached_qnn_predictor = None
    return _cached_qnn_predictor


def _run_training_background(epochs: int, qubits: int = 4, layers: int = 2, train_path: str | None = None) -> None:
    """Run training in a background thread and update training progress status."""
    global _qnn_training_status, _cached_qnn_predictor

    def callback(epoch: int, total_epochs: int, loss: float, val_loss: float) -> None:
        with _qnn_training_lock:
            _qnn_training_status.update({
                "status": "training",
                "epoch": epoch,
                "total_epochs": total_epochs,
                "loss": round(loss, 4),
                "val_loss": round(val_loss, 4),
            })

    try:
        with _qnn_training_lock:
            _qnn_training_status.update({
                "status": "training",
                "epoch": 0,
                "total_epochs": epochs,
                "loss": 0.0,
                "val_loss": 0.0,
                "error": None,
            })

        # Lazy import to prevent AppLocker/WDAC DLL blocks from crashing app startup
        from qnn.train import train_qnn_model

        # Train and collect history
        history = train_qnn_model(
            epochs=epochs,
            num_qubits=qubits,
            num_layers=layers,
            train_path=train_path,
            progress_callback=callback
        )

        # Save training history JSON
        history_path = "instance/qnn_history.json"
        os.makedirs(os.path.dirname(history_path), exist_ok=True)
        with open(history_path, "w") as f:
            json.dump(history, f)

        with _qnn_training_lock:
            _qnn_training_status["status"] = "completed"

        # Invalidate cached predictor and pre-load new trained weights
        _cached_qnn_predictor = None
        _get_qnn_predictor()

    except Exception as exc:
        logger.exception("QNN background training failed")
        with _qnn_training_lock:
            _qnn_training_status.update({
                "status": "failed",
                "error": str(exc),
            })


def _run_network_monitor_loop(app: Any) -> None:
    """Daemon thread executing periodic asynchronous QNN intrusion detection on network snapshots."""
    from qnn.utils import is_model_trained
    from qnn.predict import snapshot_to_kdd_df

    # Small delay for initial application initialization
    time.sleep(2)

    while True:
        try:
            with app.app_context():
                trained = is_model_trained()

                # Update trained status in cache
                with _cache_lock:
                    _last_prediction_cache["model_trained"] = trained
                    _last_prediction_cache["trained_status"] = "Trained" if trained else "Not Trained"

                if trained:
                    # Collect snapshot and transform into preprocessor feature-vector format
                    snapshot = network_monitor_service.get_snapshot()
                    df = snapshot_to_kdd_df(snapshot)

                    predictor = _get_qnn_predictor()
                    if predictor is not None:
                        probs = predictor.predict_probabilities(df)
                        pred = predictor.predict(df)

                        anomaly_prob = float(probs[0, 1])
                        prediction_class = int(pred[0])

                        # Log prediction to database history table asynchronously
                        log_entry = QNNPredictionHistory(
                            duration=0.0,
                            src_bytes=int(snapshot.bytes_sent),
                            dst_bytes=int(snapshot.bytes_received),
                            attack_type="Intrusion" if prediction_class == 1 else "Normal",
                            probability=anomaly_prob,
                            confidence=anomaly_prob if prediction_class == 1 else (1.0 - anomaly_prob),
                            prediction_label="Intrusion" if prediction_class == 1 else "Normal",
                        )
                        db.session.add(log_entry)
                        db.session.commit()

                        # Update thread-safe prediction cache
                        with _cache_lock:
                            _last_prediction_cache.update({
                                "anomaly_score": round(anomaly_prob, 4),
                                "prediction": "Intrusion Detected" if prediction_class == 1 else "Normal",
                                "prediction_badge_color": "danger" if prediction_class == 1 else "success",
                            })
        except Exception as exc:
            logger.exception("Error in QNN asynchronous monitoring loop")
            with _cache_lock:
                _last_prediction_cache.update({
                    "trained_status": "Inference Error",
                    "prediction": "Error",
                    "prediction_badge_color": "warning",
                    "error_message": str(exc),
                })

        time.sleep(3.0)


def start_qnn_background_monitoring(app: Any) -> None:
    """Launch the background daemon thread running the QNN network monitor loop."""
    thread = threading.Thread(
        target=_run_network_monitor_loop,
        args=(app,),
        name="qnn-monitor-loop"
    )
    thread.daemon = True
    thread.start()
    logger.info("Asynchronous QNN network monitor daemon thread started.")


@qnn_bp.route("/status", methods=["GET"])
def qnn_status() -> Any:
    """Return the cached QNN intrusion detection status instantly for low latency."""
    with _cache_lock:
        return jsonify(_last_prediction_cache.copy()), 200


@qnn_bp.route("/train", methods=["POST"])
def start_qnn_train() -> Any:
    """Trigger background thread training for the Hybrid QNN model with parameters validation."""
    global _qnn_training_status

    with _qnn_training_lock:
        if _qnn_training_status["status"] == "training":
            return jsonify({"status": "error", "message": "Training is already in progress."}), 400

    payload = request.get_json(silent=True) or {}
    
    # Validation
    try:
        epochs = int(payload.get("epochs", 10))
        qubits = int(payload.get("qubits", 4))
        layers = int(payload.get("layers", 2))
    except (ValueError, TypeError):
        return jsonify({"status": "error", "message": "Parameters must be integer types."}), 400

    if epochs < 2 or epochs > 50:
        return jsonify({"status": "error", "message": "Epochs count must be in range [2, 50]."}), 400
    if qubits not in (2, 4, 6, 8):
        return jsonify({"status": "error", "message": "Qubits count must be one of (2, 4, 6, 8)."}), 400
    if layers < 1 or layers > 10:
        return jsonify({"status": "error", "message": "Ansatz layers count must be in range [1, 10]."}), 400

    # Prefer uploaded dataset if present
    train_path = "instance/uploaded_kdd.csv"
    if not os.path.exists(train_path):
        train_path = None

    thread = threading.Thread(
        target=_run_training_background,
        args=(epochs, qubits, layers, train_path)
    )
    thread.daemon = True
    thread.start()

    return jsonify({"status": "success", "message": "Training started in background."}), 202


@qnn_bp.route("/train-status", methods=["GET"])
def get_qnn_train_status() -> Any:
    """Return the current QNN training progress metrics."""
    with _qnn_training_lock:
        return jsonify(_qnn_training_status), 200


@qnn_bp.route("/upload", methods=["POST"])
def upload_dataset() -> Any:
    """Handle custom KDD CSV dataset upload and save to instance/uploaded_kdd.csv."""
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file part in the request"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"status": "error", "message": "No file selected for upload"}), 400

    if not file.filename.endswith(".csv"):
        return jsonify({"status": "error", "message": "Invalid file format. Only CSV files allowed"}), 400

    try:
        os.makedirs("instance", exist_ok=True)
        save_path = os.path.abspath("instance/uploaded_kdd.csv")
        file.save(save_path)
        logger.info("Custom dataset uploaded and saved to: %s", save_path)
        return jsonify({"status": "success", "message": "Dataset uploaded successfully."}), 200
    except Exception as exc:
        logger.exception("Failed to save uploaded dataset")
        return jsonify({"status": "error", "message": str(exc)}), 500


@qnn_bp.route("/history", methods=["GET"])
def get_training_history() -> Any:
    """Return historical metrics from the most recent training run."""
    history_path = "instance/qnn_history.json"
    if not os.path.exists(history_path):
        return jsonify({"status": "error", "message": "No training history found."}), 404

    try:
        with open(history_path, "r") as f:
            history = json.load(f)
        return jsonify(history), 200
    except Exception as exc:
        logger.exception("Failed to load training history")
        return jsonify({"status": "error", "message": str(exc)}), 500


@qnn_bp.route("/predict", methods=["POST"])
def predict() -> Any:
    """Predict threats from raw custom connection features or batch list payloads.

    Payload schemas supported:
      - 5 Vital fields: {"duration": 0.0, "src_bytes": 100, "dst_bytes": 200, "count": 1, "srv_count": 1}
      - Full features / Batch inputs: {"features": [f1, f2, ...] or [[row1], [row2]]}
    """
    from qnn.utils import is_model_trained
    if not is_model_trained():
        return jsonify({"status": "error", "message": "QNN model is not trained yet."}), 400

    payload = request.get_json(silent=True) or {}
    
    # Case 1: Payload has a direct "features" list or list of lists
    features = payload.get("features")
    
    # Case 2: Payload contains individual vital keys
    if features is None:
        try:
            duration = float(payload.get("duration", 0.0))
            src_bytes = int(payload.get("src_bytes", 0))
            dst_bytes = int(payload.get("dst_bytes", 0))
            count = int(payload.get("count", 0))
            srv_count = int(payload.get("srv_count", 0))
            features = [duration, src_bytes, dst_bytes, count, srv_count]
        except (ValueError, TypeError):
            return jsonify({"status": "error", "message": "Missing or invalid features payload."}), 400

    # Format check and mapping
    try:
        from qnn.predict import map_features_to_df

        df = map_features_to_df(features)

        predictor = _get_qnn_predictor()
        if predictor is None:
            raise RuntimeError("Failed to load QNN model")

        # Run structured prediction
        structured_results = predictor.predict_structured(df)

        # Log predictions to database history
        for idx, res in enumerate(structured_results):
            log_entry = QNNPredictionHistory(
                duration=float(df.iloc[idx].get("duration", 0.0)),
                src_bytes=int(df.iloc[idx].get("src_bytes", 0)),
                dst_bytes=int(df.iloc[idx].get("dst_bytes", 0)),
                attack_type=res["attack_type"],
                probability=res["probability"],
                confidence=res["confidence"],
                prediction_label=res["prediction_label"],
            )
            db.session.add(log_entry)
        
        db.session.commit()

        # Return single verdict dictionary if single item, else batch list
        if len(structured_results) == 1:
            return jsonify({"status": "success", "prediction": structured_results[0]}), 200
        return jsonify({"status": "success", "predictions": structured_results}), 200

    except Exception as exc:
        logger.exception("QNN prediction request failed")
        return jsonify({"status": "error", "message": str(exc)}), 500


@qnn_bp.route("/prediction-history", methods=["GET"])
def get_prediction_history() -> Any:
    """Query and return the 15 most recent QNN manual prediction logs from database."""
    try:
        logs = QNNPredictionHistory.query.order_by(QNNPredictionHistory.timestamp.desc()).limit(15).all()
        results = []
        for log in logs:
            results.append({
                "id": log.id,
                "timestamp": log.timestamp.isoformat(),
                "duration": log.duration,
                "src_bytes": log.src_bytes,
                "dst_bytes": log.dst_bytes,
                "attack_type": log.attack_type,
                "probability": log.probability,
                "confidence": log.confidence,
                "prediction_label": log.prediction_label,
            })
        return jsonify(results), 200
    except Exception as exc:
        logger.exception("Failed to query prediction history")
        return jsonify({"status": "error", "message": str(exc)}), 500


@qnn_bp.route("/model", methods=["GET"])
def download_model() -> Any:
    """Download the trained instance/qnn_model.pth file."""
    model_path = os.path.abspath("instance/qnn_model.pth")
    if not os.path.exists(model_path):
        return jsonify({"status": "error", "message": "Model file not found. Train the model first."}), 404

    try:
        return send_file(
            model_path,
            as_attachment=True,
            download_name="qnn_model.pth",
            mimetype="application/octet-stream"
        )
    except Exception as exc:
        logger.exception("Failed to send model file")
        return jsonify({"status": "error", "message": str(exc)}), 500


@qnn_bp.route("/metrics", methods=["GET"])
def get_model_metrics() -> Any:
    """Return validation performance metrics of the currently trained model."""
    history_path = "instance/qnn_history.json"
    if not os.path.exists(history_path):
        return jsonify({"status": "error", "message": "No QNN model metrics found. Train the model first."}), 400

    try:
        with open(history_path, "r") as f:
            history = json.load(f)
        
        last_idx = len(history.get("train_loss", [])) - 1
        if last_idx < 0:
            raise ValueError("Training history contains no epochs data.")

        # Extract final epoch performance metrics
        metrics = {
            "accuracy": history["val_acc"][last_idx],
            "precision": history["val_precision"][last_idx],
            "recall": history["val_recall"][last_idx],
            "f1_score": history["val_f1"][last_idx],
            "roc_auc": history["val_auc"][last_idx],
            "confusion_matrix": history.get("confusion_matrix", []),
        }
        return jsonify({"status": "success", "metrics": metrics}), 200
    except Exception as exc:
        logger.exception("Failed to load QNN metrics")
        return jsonify({"status": "error", "message": str(exc)}), 500
