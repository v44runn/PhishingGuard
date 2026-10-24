
import pandas as pd
import joblib
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report

MODEL_PATH = Path(__file__).parent / "phishing_model.joblib"
DATA_PATH = Path(__file__).parent / "data" / "dataset.csv"


def train_model():
    print("Loading dataset...")

    df = pd.read_csv(DATA_PATH)

    df = df[["text_combined", "label"]].dropna()
    df = df[df["label"].isin([0, 1])]
    df = df.drop_duplicates(subset=["text_combined"])
    print("Unique emails:", len(df))

    X = df["text_combined"].astype(str)
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=20000,
            stop_words="english",
            ngram_range=(1, 2)
        )),
        ("classifier", LogisticRegression(
            max_iter=1000
        ))
    ])

    print("Training model...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\nMODEL EVALUATION")
    print(classification_report(y_test, predictions, zero_division=0))

    joblib.dump(model, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")


def predict_email(text):
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Email text cannot be empty")

    if not MODEL_PATH.exists():
        raise FileNotFoundError("Train the model first using python model.py")

    model = joblib.load(MODEL_PATH)

    probabilities = model.predict_proba([text])[0]

    phishing_index = list(model.classes_).index(1)

    return round(float(probabilities[phishing_index]) * 100, 2)


if __name__ == "__main__":
    train_model()
