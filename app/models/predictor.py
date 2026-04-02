import joblib
import os
import logging
from abc import ABC, abstractmethod

class BasePredictor(ABC):
    """Abstract base class for all AI models in the system."""
    @abstractmethod
    def predict(self, ja3_hash: str) -> str:
        pass

class TLSPredictor(BasePredictor):
    """
    Concrete implementation of the AI Predictor.
    Loads a pre-trained model and performs inference on JA3 hashes.
    """
    def __init__(self, model_path="saved_models/tls_model_v1.pkl"):
        self.model_path = model_path
        self.model = self._load_model()
        # Mapping labels for better UI display
        self.label_map = {0: "Benign (Regular Traffic)", 1: "Malicious (C2/Malware)"}

    def _load_model(self):
        """Loads the serialized model safely."""
        if os.path.exists(self.model_path):
            try:
                return joblib.load(self.model_path)
            except Exception as e:
                logging.error(f"Failed to load AI model: {e}")
        logging.warning("No model found. Using 'Heuristic Mode' (Rule-based fallback).")
        return None

    def predict(self, ja3_hash: str) -> str:
        """
        Performs inference. 
        Note: Real ML models usually need 'Feature Engineering' 
        (converting the hash/string to a numerical vector) before prediction.
        """
        if not self.model:
            # Fallback: Simple heuristic for demo/testing
            if ja3_hash == "d41d8cd98f00b204e9800998ecf8427e": # Example known bad hash
                return "Malicious 🚩"
            return "Benign"

        try:
            # Placeholder: Your specific feature engineering goes here
            # result = self.model.predict([vectorized_ja3])
            # return self.label_map.get(result[0], "Unknown")
            return "Analyzing..." 
        except Exception:
            return "Error"