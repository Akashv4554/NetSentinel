"""Dataset utilities and PyTorch loaders for the NSL-KDD dataset."""

from __future__ import annotations

import logging
from typing import Optional

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader, Dataset
from sklearn.model_selection import train_test_split

from qnn.preprocessing import KDDPreprocessor, NSL_KDD_COLUMNS

logger = logging.getLogger("netsentinel.qnn.dataset")


class NSLKDDDataset(Dataset):
    """PyTorch Dataset wrapper for the preprocessed NSL-KDD dataset."""

    def __init__(self, X: np.ndarray, y: np.ndarray) -> None:
        """Initialize the Dataset.

        Args:
            X: NumPy feature array of shape (num_samples, num_features).
            y: NumPy label array of shape (num_samples,).
        """
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.long)

    def __len__(self) -> int:
        """Return the number of samples in the dataset."""
        return len(self.X)

    def __getitem__(self, idx: int) -> tuple[torch.Tensor, torch.Tensor]:
        """Return a single sample (features, label) at the specified index."""
        return self.X[idx], self.y[idx]


def load_kdd_csv(filepath: str) -> pd.DataFrame:
    """Load an NSL-KDD CSV file, auto-detecting headers if present.

    Args:
        filepath: Path to the target CSV file.

    Returns:
        A pandas DataFrame containing the loaded data.
    """
    logger.debug("Loading raw CSV from %s", filepath)
    try:
        # Read the first line to check if headers exist
        preview = pd.read_csv(filepath, nrows=2)
        if preview.empty:
            return pd.DataFrame()

        # Check if the preview columns look like standard KDD column names
        # or if they are purely data rows (which indicates headerless file)
        has_header = False
        sample_col = str(preview.columns[0]).strip().lower()
        if sample_col in ("duration", "protocol_type", "service", "flag"):
            has_header = True
        elif not sample_col.replace(".", "", 1).isdigit() and len(preview.columns) > 5:
            # Check if any column header matches the standard naming conventions
            has_header = any(
                str(c).strip().lower() in [col.lower() for col in NSL_KDD_COLUMNS]
                for c in preview.columns
            )

        if has_header:
            df = pd.read_csv(filepath)
        else:
            df = pd.read_csv(filepath, header=None)

        logger.info("Loaded CSV from %s with shape %s", filepath, df.shape)
        return df
    except Exception as exc:
        logger.exception("Failed to load KDD CSV file from %s", filepath)
        raise exc


def load_nsl_kdd_loaders(
    train_path: str,
    test_path: Optional[str] = None,
    batch_size: int = 32,
    val_split: float = 0.1,
    test_split: float = 0.2,
    scale_range: tuple[float, float] = (0.0, 1.0),
    binary_classification: bool = True,
    random_state: int = 42,
    shuffle_train: bool = True,
) -> tuple[DataLoader, Optional[DataLoader], Optional[DataLoader], KDDPreprocessor]:
    """Load KDD files, run preprocessing, split datasets, and return PyTorch DataLoaders.

    Args:
        train_path: Path to the training dataset CSV.
        test_path: Optional path to the test dataset CSV. If None, test_split is used on train.
        batch_size: Batch size for the PyTorch DataLoaders.
        val_split: Fraction of training data to use for validation (e.g. 0.1).
        test_split: Fraction of training data to reserve for testing if test_path is None.
        scale_range: Min/Max target scaling boundaries for features.
        binary_classification: Map labels to binary values (0=normal, 1=anomaly).
        random_state: Seed value for reproducible random splits.
        shuffle_train: Whether to shuffle the training loader.

    Returns:
        A tuple of (train_loader, val_loader, test_loader, preprocessor).
        val_loader and test_loader may be None if splits are set to 0.0 or unavailable.
    """
    logger.info("Loading NSL-KDD loaders. Train path: %s", train_path)

    # 1. Load train dataset
    train_df = load_kdd_csv(train_path)
    if train_df.empty:
        raise ValueError(f"Training dataset loaded from {train_path} is empty.")

    # Initialize and fit preprocessor on full train dataframe
    preprocessor = KDDPreprocessor(
        scale_range=scale_range,
        binary_classification=binary_classification,
    )
    preprocessor.fit(train_df)

    # 2. Handle train / test split
    if test_path is not None:
        # Train and test are in separate files
        test_df = load_kdd_csv(test_path)
        X_train_full, y_train_full = preprocessor.transform(train_df)
        X_test, y_test = preprocessor.transform(test_df)
    else:
        # Split single train file into train and test parts
        X_all, y_all = preprocessor.transform(train_df)
        if test_split > 0.0:
            X_train_full, X_test, y_train_full, y_test = train_test_split(
                X_all,
                y_all,
                test_size=test_split,
                random_state=random_state,
                stratify=y_all,
            )
        else:
            X_train_full, y_train_full = X_all, y_all
            X_test, y_test = np.empty((0, X_all.shape[1])), np.empty((0,))

    # 3. Handle train / validation split
    if val_split > 0.0 and len(X_train_full) > 0:
        X_train, X_val, y_train, y_val = train_test_split(
            X_train_full,
            y_train_full,
            test_size=val_split,
            random_state=random_state,
            stratify=y_train_full,
        )
    else:
        X_train, y_train = X_train_full, y_train_full
        X_val, y_val = np.empty((0, X_train_full.shape[1])), np.empty((0,))

    # 4. Construct Datasets
    train_dataset = NSLKDDDataset(X_train, y_train) if len(X_train) > 0 else None
    val_dataset = NSLKDDDataset(X_val, y_val) if len(X_val) > 0 else None
    test_dataset = NSLKDDDataset(X_test, y_test) if len(X_test) > 0 else None

    # 5. Construct DataLoaders
    train_loader = (
        DataLoader(train_dataset, batch_size=batch_size, shuffle=shuffle_train)
        if train_dataset
        else None
    )
    val_loader = (
        DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
        if val_dataset
        else None
    )
    test_loader = (
        DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
        if test_dataset
        else None
    )

    logger.info(
        "PyTorch DataLoaders configured. Samples - Train: %d, Val: %d, Test: %d",
        len(train_dataset) if train_dataset else 0,
        len(val_dataset) if val_dataset else 0,
        len(test_dataset) if test_dataset else 0,
    )

    return train_loader, val_loader, test_loader, preprocessor

