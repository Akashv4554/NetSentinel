"""Evaluation metrics helpers and visual plotting utilities for the QNN classifier."""

from __future__ import annotations

import os
from typing import Any

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    roc_curve,
    precision_recall_curve,
    confusion_matrix,
    classification_report,
)

# Use 'Agg' backend to allow plot generation in headless/server environments
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def calculate_evaluation_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray | None = None
) -> dict[str, Any]:
    """Calculate and return a comprehensive set of QNN classification metrics.

    Args:
        y_true: Ground truth target labels (0=Normal, 1=Anomaly).
        y_pred: Predicted target labels (0 or 1).
        y_prob: Predicted anomaly class probabilities (floats between 0 and 1).

    Returns:
        A dictionary containing Accuracy, Precision, Recall, F1, and if y_prob is provided,
        ROC/PR curve details, Confusion Matrix, and the Classification Report.
    """
    y_true_flat = np.asarray(y_true).flatten()
    y_pred_flat = np.asarray(y_pred).flatten()

    metrics: dict[str, Any] = {
        "accuracy": float(accuracy_score(y_true_flat, y_pred_flat)),
        "precision": float(precision_score(y_true_flat, y_pred_flat, zero_division=0)),
        "recall": float(recall_score(y_true_flat, y_pred_flat, zero_division=0)),
        "f1": float(f1_score(y_true_flat, y_pred_flat, zero_division=0)),
    }

    # Add classification report (dict form for program usage)
    metrics["classification_report"] = classification_report(
        y_true_flat, y_pred_flat, output_dict=True, zero_division=0
    )
    # Also store confusion matrix
    cm = confusion_matrix(y_true_flat, y_pred_flat)
    metrics["confusion_matrix"] = cm.tolist()

    if y_prob is not None:
        y_prob_flat = np.asarray(y_prob).flatten()
        # Handle 2D probability outputs if passed [1-p, p]
        if len(y_prob.shape) > 1 and y_prob.shape[1] == 2:
            y_prob_flat = np.asarray(y_prob[:, 1]).flatten()

        try:
            metrics["auc"] = float(roc_auc_score(y_true_flat, y_prob_flat))
        except Exception:
            metrics["auc"] = 0.5

        try:
            metrics["average_precision"] = float(average_precision_score(y_true_flat, y_prob_flat))
        except Exception:
            metrics["average_precision"] = 0.5

        # Compute ROC curve details
        fpr, tpr, roc_threshs = roc_curve(y_true_flat, y_prob_flat)
        metrics["roc_curve"] = {
            "fpr": fpr.tolist(),
            "tpr": tpr.tolist(),
            "thresholds": roc_threshs.tolist()
        }

        # Compute Precision-Recall curve details
        prec, rec, pr_threshs = precision_recall_curve(y_true_flat, y_prob_flat)
        metrics["pr_curve"] = {
            "precision": prec.tolist(),
            "recall": rec.tolist(),
            "thresholds": pr_threshs.tolist()
        }

    return metrics


def plot_roc_curve(y_true: np.ndarray, y_prob: np.ndarray, save_path: str) -> None:
    """Plot the Receiver Operating Characteristic (ROC) curve and save as PNG.

    Args:
        y_true: Ground truth target labels.
        y_prob: Predicted anomaly class probabilities.
        save_path: Destination path for saving the generated image.
    """
    y_true_flat = np.asarray(y_true).flatten()
    y_prob_flat = np.asarray(y_prob).flatten()
    if len(y_prob.shape) > 1 and y_prob.shape[1] == 2:
        y_prob_flat = np.asarray(y_prob[:, 1]).flatten()

    fpr, tpr, _ = roc_curve(y_true_flat, y_prob_flat)
    try:
        auc_score = roc_auc_score(y_true_flat, y_prob_flat)
    except Exception:
        auc_score = 0.5

    plt.figure()
    plt.plot(fpr, tpr, color="darkorange", lw=2, label=f"ROC curve (AUC = {auc_score:.4f})")
    plt.plot([0, 1], [0, 1], color="navy", lw=2, linestyle="--")
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("Receiver Operating Characteristic (ROC) Curve")
    plt.legend(loc="lower right")
    plt.grid(True)

    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    plt.savefig(save_path, dpi=300, bbox_inches="tight")
    plt.close()


def plot_pr_curve(y_true: np.ndarray, y_prob: np.ndarray, save_path: str) -> None:
    """Plot the Precision-Recall (PR) curve and save as PNG.

    Args:
        y_true: Ground truth target labels.
        y_prob: Predicted anomaly class probabilities.
        save_path: Destination path for saving the generated image.
    """
    y_true_flat = np.asarray(y_true).flatten()
    y_prob_flat = np.asarray(y_prob).flatten()
    if len(y_prob.shape) > 1 and y_prob.shape[1] == 2:
        y_prob_flat = np.asarray(y_prob[:, 1]).flatten()

    precision, recall, _ = precision_recall_curve(y_true_flat, y_prob_flat)
    try:
        ap_score = average_precision_score(y_true_flat, y_prob_flat)
    except Exception:
        ap_score = 0.5

    plt.figure()
    plt.plot(recall, precision, color="blue", lw=2, label=f"PR curve (AP = {ap_score:.4f})")
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Precision-Recall (PR) Curve")
    plt.legend(loc="lower left")
    plt.grid(True)

    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    plt.savefig(save_path, dpi=300, bbox_inches="tight")
    plt.close()


def plot_confusion_matrix(y_true: np.ndarray, y_pred: np.ndarray, save_path: str) -> None:
    """Plot a visual heatmap of the Confusion Matrix and save as PNG.

    Args:
        y_true: Ground truth target labels.
        y_pred: Predicted target labels.
        save_path: Destination path for saving the generated image.
    """
    y_true_flat = np.asarray(y_true).flatten()
    y_pred_flat = np.asarray(y_pred).flatten()

    cm = confusion_matrix(y_true_flat, y_pred_flat)

    fig, ax = plt.subplots(figsize=(5, 5))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)

    classes = ["Normal", "Anomaly"]
    ax.set(
        xticks=np.arange(cm.shape[1]),
        yticks=np.arange(cm.shape[0]),
        xticklabels=classes,
        yticklabels=classes,
        title="Confusion Matrix",
        ylabel="True Label",
        xlabel="Predicted Label",
    )

    # Annotate counts inside matrix cells
    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(
                j,
                i,
                format(cm[i, j], "d"),
                ha="center",
                va="center",
                color="white" if cm[i, j] > thresh else "black",
            )

    fig.tight_layout()
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    plt.savefig(save_path, dpi=300, bbox_inches="tight")
    plt.close()
