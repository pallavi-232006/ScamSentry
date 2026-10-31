import os
import pickle
from typing import Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# Built-in balanced cybersecurity training seed for cold-start
TRAINING_SAMPLES = [
    # Scam / Phishing Samples (Label 1)
    ("URGENT: Your bank account has been suspended due to suspicious activity. Verify immediately at http://secure-bank-login.xyz", 1),
    ("Congratulations! You have won $1,000,000 in the international lottery. Send your full name, SSN, and banking details to claim.", 1),
    ("USPS: Your parcel delivery is held at terminal due to unpaid shipping tax of $1.95. Click here to confirm payment: http://usps-tracking-redirection.club", 1),
    ("Dear customer, Netflix subscription renewal failed. Update your credit card within 24 hours to prevent cancellation.", 1),
    ("IRS Final Notice: An arrest warrant has been issued in your name for tax evasion. Call 1-800-TAX-FRAUD immediately or face prosecution.", 1),
    ("WhatsApp security alert: Your 6-digit verification code was requested from another device. Reply with the code to verify your ownership.", 1),
    ("PayPal Alert: Unauthorized transaction of $649.99 detected. If this was not you, log in immediately at http://paypal-dispute-center.top", 1),
    ("Security Notice: Unusual sign-in attempt detected. Verify your password and 2FA token to protect your email inbox.", 1),
    ("You are selected for exclusive Bitcoin investment opportunity! Guaranteed 500% return in 48 hours. Deposit now to wallet.", 1),
    ("Apple Support: Your iCloud account is locked. Confirm your credentials now to unlock your device.", 1),
    
    # Benign / Legitimate Samples (Label 0)
    ("Hey mom, I will be home around 6 PM for dinner. Do you need me to pick up groceries on the way?", 0),
    ("Here is the meeting notes document from today's design sprint. Let's review the mockups tomorrow morning at 10 AM.", 0),
    ("Your appointment with Dr. Smith is confirmed for Thursday at 2:30 PM. Please arrive 15 minutes early.", 0),
    ("The package was delivered to your front porch. Thank you for shopping with us.", 0),
    ("Reminder: Team standup in 10 minutes on the main conference line.", 0),
    ("Happy birthday John! Wishing you a wonderful year ahead filled with happiness and success.", 0),
    ("Attached is the quarterly financial report for Q3. All metrics met our forecasts.", 0),
    ("Your library books are due in 3 days. You can renew them online or bring them to the branch.", 0),
    ("Can you please send me the recipe for that pasta salad you made last weekend?", 0),
    ("Great job on today's presentation! The client was very impressed with our roadmap.", 0)
]


class MLScamClassifier:
    """
    TF-IDF and Logistic Regression based machine learning detector.
    Provides statistical classification probability to complement rule-based cybersecurity analysis.
    """

    def __init__(self, model_path: str = "backend/app/data/model.pkl"):
        self.model_path = model_path
        self.vectorizer: TfidfVectorizer = None
        self.classifier: LogisticRegression = None
        self._ensure_model_trained()

    def _ensure_model_trained(self):
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, "rb") as f:
                    data = pickle.load(f)
                    self.vectorizer = data["vectorizer"]
                    self.classifier = data["classifier"]
                return
        except Exception:
            pass

        # Train on baseline samples
        texts = [text for text, _ in TRAINING_SAMPLES]
        labels = [label for _, label in TRAINING_SAMPLES]

        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            stop_words="english",
            max_features=2000,
            lowercase=True,
        )
        X = self.vectorizer.fit_transform(texts)
        self.classifier = LogisticRegression(C=1.0, max_iter=200, random_state=42)
        self.classifier.fit(X, labels)

        # Attempt to save if directory exists
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            with open(self.model_path, "wb") as f:
                pickle.dump({"vectorizer": self.vectorizer, "classifier": self.classifier}, f)
        except Exception:
            pass

    def predict_proba(self, text: str) -> float:
        """
        Returns a probability score between 0.0 and 100.0 indicating scam likelihood.
        """
        if not text or not self.vectorizer or not self.classifier:
            return 0.0

        try:
            X_vec = self.vectorizer.transform([text])
            proba = self.classifier.predict_proba(X_vec)[0][1]
            return round(float(proba) * 100.0, 1)
        except Exception:
            return 0.0
