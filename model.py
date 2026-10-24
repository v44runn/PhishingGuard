import pandas as pd
import joblib
from pathlib import Path 

from sklearn.model_selection import train_test_split  # Split training and test data
from sklearn.feature_extraction.text import TfidfVectorizer  # Convert words into numbers
from sklearn.linear_model import LogisticRegression  # Classify emails
from sklearn.pipeline import Pipeline  # Combine text processing and classification
from sklearn.metrics import classification_report  # Evaluate model performance

MODEL_PATH = Path(__file__).parent / "phishing_model.joblib"  # Saved model location
DATA_PATH = Path(__file__).parent / "data" / "dataset.csv"  # Dataset location


def train_model():  # Train and save the phishing classifier
    print("Loading dataset...")  # Show progress

    df = pd.read_csv(DATA_PATH)  # Load the CSV

    df = df[["text_combined", "label"]].dropna()  # Keep the required columns and remove missing values
    df = df[df["label"].isin([0, 1])]  # Keep only valid class labels
    df = df.drop_duplicates(subset=["text_combined"])  # Remove identical emails before splitting
    print("Unique emails:", len(df))  # Display the number of emails remaining

    X = df["text_combined"].astype(str)  # Email text used as input
    y = df["label"].astype(int)  # Correct classification for each email

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )  # Reserve 20% of emails for evaluation

    model = Pipeline([  # Build the complete ML pipeline
        ("tfidf", TfidfVectorizer(
            max_features=10000,  # Keep up to 10,000 text features
            stop_words="english"  # Remove common English stop words
        )),
        ("classifier", LogisticRegression(
            max_iter=1000  # Allow enough iterations for training
        ))
    ])

    print("Training model...")  # Show progress
    model.fit(X_train, y_train)  # Learn from the training emails

    predictions = model.predict(X_test)  # Predict unseen test emails

    print("\nMODEL EVALUATION")  # Display evaluation heading
    print(classification_report(y_test, predictions, zero_division=0))  # Show precision, recall, F1

    joblib.dump(model, MODEL_PATH)  # Save the entire trained pipeline
    print(f"\nModel saved to {MODEL_PATH}")  # Confirm saved location


def predict_email(text):  # Function used by the frontend
    if not isinstance(text, str) or not text.strip():  # Validate input
        raise ValueError("Email text cannot be empty")  # Reject invalid input

    if not MODEL_PATH.exists():  # Check whether model has been trained
        raise FileNotFoundError("Train the model first using python model.py")

    model = joblib.load(MODEL_PATH)  # Load the saved model

    probabilities = model.predict_proba([text])[0]  # Get class probabilities

    phishing_index = list(model.classes_).index(1)  # Find phishing class (assumed label 1)

    return round(float(probabilities[phishing_index]) * 100, 2)  # Return percentage


if __name__ == "__main__":  # Only train when this file is run directly
    train_model()  # Start training