"""Training pipeline for the Hybrid QNN on NSL-KDD network data."""

from __future__ import annotations

import logging
import os
import pickle
import tempfile
from typing import Any

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.optim.lr_scheduler import ReduceLROnPlateau
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

from qnn.dataset import load_nsl_kdd_loaders
from qnn.model import HybridQNN
from qnn.preprocessing import KDDPreprocessor, NSL_KDD_COLUMNS

logger = logging.getLogger("netsentinel.qnn.train")


def generate_fallback_mock_data(num_samples: int = 200) -> str:
    """Generate a mock NSL-KDD dataset CSV file for fallback training."""
    temp_dir = tempfile.gettempdir()
    file_path = os.path.join(temp_dir, "fallback_kdd_train.csv")

    rows = []
    for _ in range(num_samples):
        # Match standard NSL-KDD structure
        duration = float(np.random.randint(0, 1000))
        protocol = np.random.choice(["tcp", "udp", "icmp"])
        service = np.random.choice(["http", "private", "ftp", "smtp", "domain_u"])
        flag = np.random.choice(["SF", "S0", "REJ", "RSTR"])
        nums = [float(np.random.randint(0, 5000)) for _ in range(37)]
        # Map label to either normal or an attack
        label = np.random.choice(["normal", "neptune", "satan", "portsweep"])
        diff_score = int(np.random.randint(0, 21))

        row = [duration, protocol, service, flag] + nums + [label, diff_score]
        rows.append(",".join(map(str, row)))

    with open(file_path, "w") as f:
        f.write("\n".join(rows))

    logger.info("Generated fallback mock NSL-KDD data at: %s", file_path)
    return file_path


def train_qnn_model(
    train_path: str | None = None,
    test_path: str | None = None,
    model_save_path: str = "instance/qnn_model.pth",
    preprocessor_save_path: str = "instance/qnn_preprocessor.pkl",
    epochs: int = 10,
    batch_size: int = 32,
    learning_rate: float = 0.01,
    num_qubits: int = 4,
    num_layers: int = 2,
    patience: int = 5,
    progress_callback: Any = None,
) -> dict[str, Any]:
    """Train the HybridQNN model and persist the best checkpoint.

    Args:
        train_path: Path to the training dataset CSV. If None/missing, generates fallback mock data.
        test_path: Optional path to the test dataset CSV.
        model_save_path: Output checkpoint path for model.
        preprocessor_save_path: Output serialization path for preprocessor.
        epochs: Max training epoch count.
        batch_size: Loader batch size.
        learning_rate: Optimizer learning rate.
        num_qubits: Qubit count in VQC.
        num_layers: Depth count of variational ansatz.
        patience: Epochs to wait for improvement in validation loss before early stopping.
        progress_callback: Optional callable for logging training steps.

    Returns:
        A dictionary containing historical metric records (loss, metrics, confusion matrix).
    """
    logger.info("Starting QNN training pipeline...")

    # 1. Fallback to mock data if no file is provided or exists
    is_mock = False
    temp_file_to_clean = None
    if not train_path or not os.path.exists(train_path):
        logger.warning("Train dataset path %s not found. Using auto-generated mock data.", train_path)
        temp_file_to_clean = generate_fallback_mock_data(num_samples=250)
        train_path = temp_file_to_clean
        is_mock = True

    try:
        # 2. Configure dataloaders
        train_loader, val_loader, _, preprocessor = load_nsl_kdd_loaders(
            train_path=train_path,
            test_path=test_path if (test_path and os.path.exists(test_path)) else None,
            batch_size=batch_size,
            val_split=0.2,
            test_split=0.0,
            scale_range=(0.0, 1.0),
            binary_classification=True,
            random_state=42,
        )

        # 3. Determine feature dimensions
        input_dim = 0
        for X_batch, _ in train_loader:
            input_dim = X_batch.shape[1]
            break

        if input_dim == 0:
            raise ValueError("Training dataset contains no features.")

        logger.info("Fitted preprocessor output dimension: %d", input_dim)

        # 4. Initialize model, optimizer, loss function, and scheduler
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model = HybridQNN(input_dim=input_dim, num_qubits=num_qubits, num_layers=num_layers)
        model.to(device)

        optimizer = optim.Adam(model.parameters(), lr=learning_rate)
        criterion = nn.BCELoss()
        scheduler = ReduceLROnPlateau(optimizer, mode="min", factor=0.5, patience=2)

        history: dict[str, list[Any]] = {
            "train_loss": [],
            "train_acc": [],
            "val_loss": [],
            "val_acc": [],
            "val_precision": [],
            "val_recall": [],
            "val_f1": [],
            "val_auc": [],
        }

        best_val_loss = float("inf")
        best_model_state = None
        epochs_no_improve = 0

        # 5. Execute training epochs
        for epoch in range(epochs):
            model.train()
            total_loss = 0.0
            correct = 0
            total = 0

            for X_batch, y_batch in train_loader:
                X_batch, y_batch = X_batch.to(device), y_batch.to(device)
                y_batch = y_batch.unsqueeze(1).float()

                # Zero parameter gradients
                optimizer.zero_grad()

                # Forward pass
                outputs = model(X_batch)
                loss = criterion(outputs, y_batch)

                # Backward and optimize
                loss.backward()
                optimizer.step()

                total_loss += loss.item() * X_batch.size(0)
                predicted = (outputs >= 0.5).float()
                total += y_batch.size(0)
                correct += (predicted == y_batch).sum().item()

            epoch_loss = total_loss / total
            epoch_acc = correct / total
            history["train_loss"].append(epoch_loss)
            history["train_acc"].append(epoch_acc)

            # Validation pass with full metrics collection
            val_loss = 0.0
            model.eval()

            all_y_true = []
            all_y_pred = []
            all_y_prob = []

            with torch.no_grad():
                for X_val, y_val in val_loader:
                    X_val, y_val = X_val.to(device), y_val.to(device)
                    y_val = y_val.unsqueeze(1).float()
                    val_outputs = model(X_val)
                    loss_val = criterion(val_outputs, y_val)

                    val_loss += loss_val.item() * X_val.size(0)
                    val_predicted = (val_outputs >= 0.5).float()

                    all_y_true.extend(y_val.cpu().numpy().flatten())
                    all_y_pred.extend(val_predicted.cpu().numpy().flatten())
                    all_y_prob.extend(val_outputs.cpu().numpy().flatten())

            epoch_val_loss = val_loss / len(all_y_true)
            
            # Compute classification metrics
            all_y_true_np = np.array(all_y_true)
            all_y_pred_np = np.array(all_y_pred)
            all_y_prob_np = np.array(all_y_prob)

            epoch_val_acc = accuracy_score(all_y_true_np, all_y_pred_np)
            epoch_val_precision = precision_score(all_y_true_np, all_y_pred_np, zero_division=0)
            epoch_val_recall = recall_score(all_y_true_np, all_y_pred_np, zero_division=0)
            epoch_val_f1 = f1_score(all_y_true_np, all_y_pred_np, zero_division=0)
            
            try:
                epoch_val_auc = roc_auc_score(all_y_true_np, all_y_prob_np)
            except Exception:
                epoch_val_auc = 0.5  # Fallback if only one class is present in validation batch

            history["val_loss"].append(epoch_val_loss)
            history["val_acc"].append(epoch_val_acc)
            history["val_precision"].append(epoch_val_precision)
            history["val_recall"].append(epoch_val_recall)
            history["val_f1"].append(epoch_val_f1)
            history["val_auc"].append(epoch_val_auc)

            logger.info(
                "Epoch %d/%d - Loss: %.4f, Acc: %.4f | Val Loss: %.4f, Val Acc: %.4f, F1: %.4f, AUC: %.4f",
                epoch + 1,
                epochs,
                epoch_loss,
                epoch_acc,
                epoch_val_loss,
                epoch_val_acc,
                epoch_val_f1,
                epoch_val_auc,
            )

            if progress_callback:
                progress_callback(epoch + 1, epochs, epoch_loss, epoch_val_loss)

            # Update Learning Rate Scheduler
            scheduler.step(epoch_val_loss)

            # Check for Best Checkpoint & Early Stopping
            if epoch_val_loss < best_val_loss:
                best_val_loss = epoch_val_loss
                best_model_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
                epochs_no_improve = 0
            else:
                epochs_no_improve += 1
                if epochs_no_improve >= patience:
                    logger.info("Early stopping triggered due to validation plateau.")
                    break

        # 6. Load Best Model state and log final confusion matrix
        if best_model_state is not None:
            model.load_state_dict(best_model_state)
            logger.info("Loaded best model state from epoch with val loss: %.4f", best_val_loss)

        # Generate final metrics for logging the confusion matrix
        model.eval()
        final_y_true = []
        final_y_pred = []
        with torch.no_grad():
            for X_val, y_val in val_loader:
                X_val, y_val = X_val.to(device), y_val.to(device)
                y_val = y_val.unsqueeze(1).float()
                val_outputs = model(X_val)
                val_predicted = (val_outputs >= 0.5).float()
                final_y_true.extend(y_val.cpu().numpy().flatten())
                final_y_pred.extend(val_predicted.cpu().numpy().flatten())

        cm = confusion_matrix(np.array(final_y_true), np.array(final_y_pred))
        logger.info("Final Confusion Matrix:\n%s", cm)
        history["confusion_matrix"] = cm.tolist()

        # 7. Save model checkpoint and preprocessor
        os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
        os.makedirs(os.path.dirname(preprocessor_save_path), exist_ok=True)

        checkpoint = {
            "state_dict": model.state_dict(),
            "input_dim": input_dim,
            "num_qubits": num_qubits,
            "num_layers": num_layers,
        }
        torch.save(checkpoint, model_save_path)

        with open(preprocessor_save_path, "wb") as f:
            pickle.dump(preprocessor, f)

        logger.info("QNN training pipeline completed successfully. Artifacts saved.")
        return history

    finally:
        # Clean up temp file
        if temp_file_to_clean and os.path.exists(temp_file_to_clean):
            os.remove(temp_file_to_clean)
            logger.info("Cleaned up temp mock file: %s", temp_file_to_clean)


if __name__ == "__main__":
    # Test script if executed directly
    logging.basicConfig(level=logging.INFO)
    train_qnn_model(epochs=3)
