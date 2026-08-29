"""Hybrid Classical-Quantum Neural Network binary classifier model using PyTorch and PennyLane."""

from __future__ import annotations

import torch
import torch.nn as nn

from qnn.circuits import PennyLaneVQC


class HybridQNN(nn.Module):
    """Hybrid Classical-Quantum Binary Classifier.

    Architecture:
        Input
          ↓
      Dense Layer (classical_reducer)
          ↓
     Quantum Layer (vqc)
          ↓
      Dense Layer (classifier)
          ↓
       Sigmoid Output

    This model reduces high-dimensional raw network inputs to lower-dimensional
    quantum feature angles, evaluates expectations via a Variational Quantum
    Circuit (VQC) with StronglyEntanglingLayers, and classifies the outcomes
    using a final single-neuron Sigmoid layer.
    """

    def __init__(self, input_dim: int, num_qubits: int = 4, num_layers: int = 2) -> None:
        """Initialize the HybridQNN model.

        Args:
            input_dim: Dimension of raw preprocessed features (e.g. 122).
            num_qubits: Qubit count in the VQC (2, 4, 6, or 8).
            num_layers: Depth count of StronglyEntanglingLayers.
        """
        super().__init__()
        self.num_qubits = num_qubits
        self.num_layers = num_layers

        # 1. Classical Dense Layer (reduction to qubit count)
        self.dense_1 = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Dropout(p=0.1),
            nn.Linear(64, num_qubits),
            nn.Tanh(),  # Tanh maps to [-1, 1], scaling nicely to [-pi, pi]
        )

        # 2. Quantum Layer (StronglyEntanglingLayers and AngleEmbedding)
        self.vqc = PennyLaneVQC(num_qubits=num_qubits, num_layers=num_layers)

        # 3. Final Dense Layer mapping expectations to a single output logit
        self.dense_2 = nn.Linear(num_qubits, 1)

        # 4. Sigmoid Output mapping logit to probability in [0, 1]
        self.sigmoid = nn.Sigmoid()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass of the hybrid model.

        Args:
            x: Input feature batch of shape (batch_size, input_dim).

        Returns:
            Anomaly probability tensor of shape (batch_size, 1) in range [0, 1].
        """
        # Dense Layer 1
        reduced = self.dense_1(x)
        
        # Scale to [-pi, pi] for Bloch-sphere angle embedding
        angles = reduced * torch.pi

        # Quantum Layer
        q_out = self.vqc(angles)

        # Dense Layer 2
        logits = self.dense_2(q_out)

        # Sigmoid Output
        probs = self.sigmoid(logits)
        return probs
