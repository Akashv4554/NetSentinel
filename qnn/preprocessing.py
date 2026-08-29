"""Preprocessing utilities for the NSL-KDD dataset."""

from __future__ import annotations

import logging
from typing import Optional, Sequence

import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder

logger = logging.getLogger("netsentinel.qnn.preprocessing")

# Standard 43 columns for the NSL-KDD dataset (including difficulty_score)
NSL_KDD_COLUMNS = [
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
    "dst_host_srv_rerror_rate", "label", "difficulty_score"
]

CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]


class KDDPreprocessor:
    """Preprocessor for clean, normalized, and encoded NSL-KDD feature sets."""

    def __init__(
        self,
        scale_range: tuple[float, float] = (0.0, 1.0),
        binary_classification: bool = True,
    ) -> None:
        """Initialize the preprocessor.

        Args:
            scale_range: Target range for scaling numerical features.
            binary_classification: If True, maps labels to binary (0=normal, 1=attack).
        """
        self.scale_range = scale_range
        self.binary_classification = binary_classification

        self._scaler = MinMaxScaler(feature_range=scale_range)
        try:
            self._encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
        except TypeError:  # Support older versions of scikit-learn
            self._encoder = OneHotEncoder(handle_unknown="ignore", sparse=False)  # type: ignore[call-arg]

        self._fitted = False
        self._numeric_cols: list[str] = []
        self._categorical_cols: list[str] = []
        self._imputation_values: dict[str, object] = {}
        self._label_map: dict[str, int] = {}
        self._reverse_label_map: dict[int, str] = {}

    def fit(self, df: pd.DataFrame) -> KDDPreprocessor:
        """Fit scaler, encoder, and imputation configurations on training data.

        Args:
            df: Training dataframe containing raw NSL-KDD columns.

        Returns:
            The fitted KDDPreprocessor instance.
        """
        logger.info("Fitting KDDPreprocessor on training data shape: %s", df.shape)

        # Work on a copy of dataframe to avoid Side-Effects
        df_copy = df.copy()

        # Handle missing column headers dynamically
        if df_copy.shape[1] == len(NSL_KDD_COLUMNS):
            df_copy.columns = NSL_KDD_COLUMNS
        elif df_copy.shape[1] == len(NSL_KDD_COLUMNS) - 1:
            df_copy.columns = NSL_KDD_COLUMNS[:-1]
        else:
            logger.warning(
                "Dataframe column count (%d) mismatch with NSL-KDD defaults (%d). Using raw labels.",
                df_copy.shape[1],
                len(NSL_KDD_COLUMNS),
            )

        # Drop the difficulty_score if present, as it is a metadata rating and not a feature
        if "difficulty_score" in df_copy.columns:
            df_copy = df_copy.drop(columns=["difficulty_score"])

        # Determine feature column names (excluding label)
        feature_cols = [col for col in df_copy.columns if col != "label"]

        self._numeric_cols = [
            col for col in feature_cols if col not in CATEGORICAL_COLUMNS
        ]
        self._categorical_cols = [
            col for col in feature_cols if col in CATEGORICAL_COLUMNS
        ]

        # Calculate imputation values (median for numeric, mode for categorical)
        for col in self._numeric_cols:
            self._imputation_values[col] = df_copy[col].median()
        for col in self._categorical_cols:
            mode_series = df_copy[col].mode()
            self._imputation_values[col] = mode_series.iloc[0] if not mode_series.empty else "unknown"

        # Apply imputation before fitting transformers to ensure no NaNs are passed
        imputed_df = self._impute(df_copy)

        # Fit numerical scaler
        if self._numeric_cols:
            self._scaler.fit(imputed_df[self._numeric_cols].values.astype(np.float64))

        # Fit categorical one-hot encoder
        if self._categorical_cols:
            self._encoder.fit(imputed_df[self._categorical_cols].values.astype(str))

        # Fit label map for classification
        if "label" in imputed_df.columns:
            unique_labels = imputed_df["label"].unique()
            if self.binary_classification:
                # 0 for normal, 1 for any attack class
                self._label_map = {
                    lbl: 0 if self._is_normal_label(lbl) else 1
                    for lbl in unique_labels
                }
            else:
                # Multi-class mapping
                sorted_labels = sorted(list(unique_labels))
                self._label_map = {lbl: idx for idx, lbl in enumerate(sorted_labels)}
                self._reverse_label_map = {idx: lbl for idx, lbl in enumerate(sorted_labels)}

        self._fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        """Apply learned scaling, encoding, and imputation to raw data.

        Args:
            df: Dataframe to transform.

        Returns:
            A tuple (X, y) of NumPy arrays where:
                X: Float64 array of shape (num_samples, num_features).
                y: Int64 array of shape (num_samples,). If label column is not present,
                   returns an array of zeros.
        """
        if not self._fitted:
            raise ValueError("KDDPreprocessor must be fitted before calling transform.")

        df_copy = df.copy()

        # Handle column assignment matches
        if df_copy.shape[1] == len(NSL_KDD_COLUMNS):
            df_copy.columns = NSL_KDD_COLUMNS
        elif df_copy.shape[1] == len(NSL_KDD_COLUMNS) - 1:
            df_copy.columns = NSL_KDD_COLUMNS[:-1]

        if "difficulty_score" in df_copy.columns:
            df_copy = df_copy.drop(columns=["difficulty_score"])

        # Impute missing values using fitted defaults
        imputed_df = self._impute(df_copy)

        # Preprocess features
        X_num = np.empty((len(imputed_df), 0))
        if self._numeric_cols:
            X_num = self._scaler.transform(
                imputed_df[self._numeric_cols].values.astype(np.float64)
            )

        X_cat = np.empty((len(imputed_df), 0))
        if self._categorical_cols:
            X_cat = self._encoder.transform(
                imputed_df[self._categorical_cols].values.astype(str)
            )

        X = np.hstack([X_num, X_cat])

        # Preprocess labels
        if "label" in imputed_df.columns:
            y = imputed_df["label"].map(self._label_map).fillna(1).values.astype(np.int64)
        else:
            y = np.zeros(len(imputed_df), dtype=np.int64)

        return X, y

    def fit_transform(self, df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        """Fit to the data and then transform it.

        Args:
            df: Dataframe to fit and transform.

        Returns:
            A tuple (X, y) of transformed NumPy arrays.
        """
        return self.fit(df).transform(df)

    def decode_label(self, encoded_label: int) -> str:
        """Decode integer prediction back to categorical name (for multi-class mode)."""
        if self.binary_classification:
            return "normal" if encoded_label == 0 else "anomaly"
        return self._reverse_label_map.get(encoded_label, "unknown")

    def _impute(self, df: pd.DataFrame) -> pd.DataFrame:
        """Impute missing values using self._imputation_values."""
        imputed = df.copy()
        for col, val in self._imputation_values.items():
            if col in imputed.columns:
                imputed[col] = imputed[col].fillna(val)
        return imputed

    @staticmethod
    def _is_normal_label(label: str) -> bool:
        """Determine whether a label refers to normal network traffic."""
        normalized = str(label).strip().lower()
        return normalized in ("normal", "normal.", "0")

