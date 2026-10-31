import os
import json
import pickle
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    confusion_matrix,
)

# Canonical dataset and artifact paths
BASE_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
DATASET_PATH = os.path.join(BASE_DATA_DIR, "dataset.json")
MODEL_PATH = os.path.join(BASE_DATA_DIR, "model.pkl")
METRICS_PATH = os.path.join(BASE_DATA_DIR, "model_metrics.json")

DATASET_LIMITATIONS = [
    "Trained on a curated reference dataset of 80 labeled security scenarios; variance may exist on novel out-of-distribution text.",
    "Short SMS messages containing exclusively novel slang, obfuscated leetspeak, or emojis may produce low TF-IDF feature overlap.",
    "Designed strictly as a complementary secondary scoring vector (35% maximum blended weight) alongside deterministic cybersecurity heuristics.",
    "Does not replace human threat intelligence or live threat feed reputation lookups."
]


class MLScamClassifier:
    """
    Local TF-IDF and Logistic Regression Machine Learning Classifier.
    Evaluates probabilistic scam patterns locally with zero network or third-party API dependencies.
    """

    _instance: Optional["MLScamClassifier"] = None

    def __new__(cls, *args, **kwargs):
        # Singleton pattern to prevent repeated disk loading across router requests
        if cls._instance is None:
            cls._instance = super(MLScamClassifier, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(
        self,
        model_path: str = MODEL_PATH,
        dataset_path: str = DATASET_PATH,
        metrics_path: str = METRICS_PATH,
    ):
        if self._initialized:
            return

        self.model_path = model_path
        self.dataset_path = dataset_path
        self.metrics_path = metrics_path
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.classifier: Optional[LogisticRegression] = None
        self.metrics: Dict[str, Any] = {}

        self._load_or_train()
        self._initialized = True

    def _load_or_train(self):
        """Loads cached model artifact from disk or executes stratified training."""
        if os.path.exists(self.model_path) and os.path.exists(self.metrics_path):
            try:
                with open(self.model_path, "rb") as f:
                    artifacts = pickle.load(f)
                    self.vectorizer = artifacts.get("vectorizer")
                    self.classifier = artifacts.get("classifier")

                with open(self.metrics_path, "r", encoding="utf-8") as f:
                    self.metrics = json.load(f)
                return
            except Exception:
                # If cached artifacts are corrupt or incompatible, retrain
                pass

        self.train_and_evaluate()

    def train_and_evaluate(self) -> Dict[str, Any]:
        """
        Executes stratified train/test split, fits TF-IDF vectorizer + LogisticRegression,
        evaluates precision, recall, F1, and confusion matrix, and persists artifacts.
        """
        if not os.path.exists(self.dataset_path):
            raise FileNotFoundError(f"Training dataset not found at {self.dataset_path}")

        with open(self.dataset_path, "r", encoding="utf-8") as f:
            records = json.load(f)

        texts = [r["text"] for r in records]
        labels = [int(r["label"]) for r in records]

        # Stratified 75% train / 25% test split
        X_train_raw, X_test_raw, y_train, y_test = train_test_split(
            texts,
            labels,
            test_size=0.25,
            stratify=labels,
            random_state=42,
        )

        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            sublinear_tf=True,
            max_features=1500,
            lowercase=True,
            strip_accents="unicode",
        )

        X_train = self.vectorizer.fit_transform(X_train_raw)
        X_test = self.vectorizer.transform(X_test_raw)

        self.classifier = LogisticRegression(
            C=1.5,
            max_iter=300,
            random_state=42,
            solver="liblinear",
        )
        self.classifier.fit(X_train, y_train)

        # Evaluate on holdout test set
        y_pred = self.classifier.predict(X_test)

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        cm = confusion_matrix(y_test, y_pred).tolist()

        self.metrics = {
            "model_type": "TF-IDF + Logistic Regression",
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": cm,  # [[TN, FP], [FN, TP]]
            "train_samples": len(X_train_raw),
            "test_samples": len(X_test_raw),
            "total_dataset_samples": len(records),
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "limitations": DATASET_LIMITATIONS,
        }

        # Persist artifacts to disk
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, "wb") as f:
            pickle.dump({"vectorizer": self.vectorizer, "classifier": self.classifier}, f)

        with open(self.metrics_path, "w", encoding="utf-8") as f:
            json.dump(self.metrics, f, indent=2)

        return self.metrics

    def predict_proba(self, text: str) -> float:
        """
        Returns a probability score between 0.0 and 100.0 indicating scam likelihood.
        Handles empty, whitespace, and unfamiliar inputs gracefully.
        """
        if not text or not text.strip() or self.vectorizer is None or self.classifier is None:
            return 0.0

        try:
            vec = self.vectorizer.transform([text.strip()])
            # Check if input had zero non-zero features in vocabulary
            if vec.nnz == 0:
                # Completely unfamiliar tokens -> 0.0 probability, not an assumed scam
                return 0.0

            proba = self.classifier.predict_proba(vec)[0][1]
            return round(float(proba) * 100.0, 1)
        except Exception:
            return 0.0

    def get_analysis(self, text: str) -> Dict[str, Any]:
        """
        Produces detailed ML analysis payload for explainable threat reports.
        """
        proba = self.predict_proba(text)
        
        # Determine classification label
        if proba >= 70.0:
            pred_label = "SCAM_LIKELY"
        elif proba >= 40.0:
            pred_label = "SUSPICIOUS_LINGUISTIC_PATTERNS"
        else:
            pred_label = "BENIGN_PATTERN"

        # Extract top contributing n-grams if available
        top_features = []
        if text and self.vectorizer and self.classifier:
            try:
                vec = self.vectorizer.transform([text.strip()])
                feature_names = self.vectorizer.get_feature_names_out()
                coefs = self.classifier.coef_[0]
                
                # Active non-zero features in this text
                non_zero_indices = vec.nonzero()[1]
                contributions = []
                for idx in non_zero_indices:
                    weight = coefs[idx] * vec[0, idx]
                    if weight > 0:
                        contributions.append((feature_names[idx], round(float(weight), 3)))

                # Sort descending by positive weight (scam indicator)
                contributions.sort(key=lambda x: x[1], reverse=True)
                top_features = [f"{term} (+{w})" for term, w in contributions[:5]]
            except Exception:
                pass

        return {
            "model_type": "TF-IDF + Logistic Regression",
            "scam_probability": proba,
            "prediction_label": pred_label,
            "top_contributing_ngrams": top_features,
            "model_metrics": {
                "precision": self.metrics.get("precision", 0.0),
                "recall": self.metrics.get("recall", 0.0),
                "f1_score": self.metrics.get("f1_score", 0.0),
                "test_accuracy": self.metrics.get("accuracy", 0.0),
                "confusion_matrix": self.metrics.get("confusion_matrix", []),
            },
            "limitations": DATASET_LIMITATIONS,
        }
