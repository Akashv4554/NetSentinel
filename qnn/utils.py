"""General utility functions for the QNN pipeline module."""

from __future__ import annotations

import os


def is_model_trained(
    model_path: str = "instance/qnn_model.pth",
    preprocessor_path: str = "instance/qnn_preprocessor.pkl",
) -> bool:
    """Verify whether a trained QNN model and its preprocessor exist on disk.

    Args:
        model_path: Checked path for the model weights checkpoint.
        preprocessor_path: Checked path for the preprocessor serialization.

    Returns:
        True if both files exist, False otherwise.
    """
    return os.path.exists(model_path) and os.path.exists(preprocessor_path)
