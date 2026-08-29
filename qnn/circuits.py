"""PennyLane-based Variational Quantum Circuit (VQC) module."""

from __future__ import annotations

import pennylane as qml
import torch
import torch.nn as nn


class PennyLaneVQC(nn.Module):
    """Configurable Variational Quantum Classifier Layer using PennyLane.

    This module supports 2, 4, 6, and 8 qubits, embeds inputs using
    AngleEmbedding (RY rotations), applies StronglyEntanglingLayers,
    and measures PauliZ expectation values.
    """

    def __init__(self, num_qubits: int = 4, num_layers: int = 2) -> None:
        """Initialize the VQC module.

        Args:
            num_qubits: Qubit count. Must be one of 2, 4, 6, 8.
            num_layers: Depth count of variational strongly entangling layers.
        """
        super().__init__()
        if num_qubits not in (2, 4, 6, 8):
            raise ValueError(f"num_qubits must be one of (2, 4, 6, 8). Got {num_qubits}")

        self.num_qubits = num_qubits
        self.num_layers = num_layers

        # 1. Define quantum simulator device
        dev = qml.device("default.qubit", wires=num_qubits)

        # 2. Define the QNode function
        @qml.qnode(dev, interface="torch")
        def circuit(inputs: torch.Tensor, weights: torch.Tensor) -> list[qml.measure]:
            """PennyLane QNode circuit.

            Args:
                inputs: Scaled input features, shape (num_qubits,).
                weights: Variational layers parameters, shape (num_layers, num_qubits, 3).
            """
            # Encode inputs into quantum states using Y-rotation angles
            qml.AngleEmbedding(inputs, wires=range(num_qubits), rotation="Y")
            
            # Apply StronglyEntanglingLayers ansatz
            qml.StronglyEntanglingLayers(weights, wires=range(num_qubits))
            
            # Return PauliZ expectation value for each qubit
            return [qml.expval(qml.PauliZ(i)) for i in range(num_qubits)]

        # 3. Define parameter shapes for the TorchLayer wrapper
        # StronglyEntanglingLayers requires shape (num_layers, num_qubits, 3)
        weight_shapes = {"weights": (num_layers, num_qubits, 3)}
        
        # Wrap QNode in TorchLayer for seamless PyTorch nn.Module integration
        self.q_layer = qml.qnn.TorchLayer(circuit, weight_shapes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass executing the VQC.

        Args:
            x: Input tensor of shape (batch_size, num_qubits).

        Returns:
            Expectation values of shape (batch_size, num_qubits).
        """
        return self.q_layer(x)
