import json
import os
import re
from typing import Dict, Optional, Tuple

import kagglehub
import pandas as pd

DATASET_HANDLE = "naserabdullahalam/phishing-email-dataset"
DEFAULT_KEYWORDS_OUTPUT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "suspicious_keywords.json")

# Candidate suspicious phrases across key phishing categories
CANDIDATE_PHRASES = [
    # Urgency & Panic
    ("urgent", "urgency", "Urgent language creates artificial urgency and time pressure to rush the recipient into acting without thinking."),
    ("act now", "urgency", "Creates artificial urgency and time pressure to rush the recipient into acting without thinking."),
    ("immediate action required", "urgency", "Pressures the recipient to act promptly without verifying the request."),
    ("within 24 hours", "urgency", "Imposes an artificial deadline to force hasty compliance."),
    ("urgent notice", "urgency", "Attempts to induce panic and bypass normal scrutiny."),
    ("final warning", "urgency", "Uses intimidation and artificial scarcity to prompt immediate response."),
    ("failure to respond", "urgency", "Threatens negative consequences if action is not taken quickly."),
    ("action required immediately", "urgency", "High urgency indicator designed to prevent recipient diligence."),
    ("limited time", "urgency", "Manufactures urgency to rush the recipient."),
    
    # Account Alerts & Intimidation
    ("account suspended", "account_alert", "Threatens account suspension and loss of service to coerce immediate action."),
    ("suspended", "account_alert", "References account suspension, a common phishing lure to provoke panic."),
    ("unauthorized login", "account_alert", "Fake security alert designed to provoke panicked credential submission."),
    ("unusual activity detected", "account_alert", "Pretends to detect fraud to lure user into an attacker-controlled login page."),
    ("security alert", "account_alert", "Impersonates security teams to establish false authority."),
    ("locked out", "account_alert", "Leverages fear of losing access to sensitive accounts."),
    ("verify your account", "account_alert", "Common phishing pretext to harvest credentials via spoofed verification forms."),
    ("confirm your identity", "account_alert", "Prompts for personal data under the guise of an identity verification check."),
    ("reactivate your account", "account_alert", "Lures recipient to fake portal under the pretext of restoring access."),
    
    # Sensitive Credential Harvesting
    ("password", "sensitive_info", "References passwords, frequently targeted in credential harvesting schemes."),
    ("enter your password", "sensitive_info", "Direct solicitation of account passwords via email is a primary phishing indicator."),
    ("send your password", "sensitive_info", "Legitimate organizations never ask users to transmit passwords via email."),
    ("confirm your ssn", "sensitive_info", "Requests Social Security Number, which is sensitive PII used in identity theft."),
    ("social security", "sensitive_info", "Requests or references Social Security details, highly sensitive personal data."),
    ("credit card number", "sensitive_info", "Solicits payment card numbers to conduct unauthorized transactions."),
    ("banking credentials", "sensitive_info", "Requests confidential banking login information."),
    ("security questions", "sensitive_info", "Attempts to capture security question answers used for account recovery."),
    ("seed phrase", "sensitive_info", "Requests cryptocurrency wallet secret recovery phrase; guarantees wallet theft."),
    ("verification code", "sensitive_info", "Attempts to intercept Multi-Factor Authentication (MFA/2FA) one-time codes."),
    ("provide your pin", "sensitive_info", "Requests personal identification numbers for banking or debit access."),
    
    # Financial & Transaction Lures
    ("wire transfer", "financial", "Often indicates Business Email Compromise (BEC) or urgent payment diversion scams."),
    ("payment declined", "financial", "Falsely claims billing failure to trick recipient into entering payment details."),
    ("refund pending", "financial", "Uses unexpected financial gains to lure recipient into clicking dangerous links."),
    ("crypto invoice", "financial", "Unsolicited cryptocurrency payment demands or fake receipt lures."),
]


def load_email_dataset(filename: str = "CEAS_08.csv") -> pd.DataFrame:
    """
    Download/resolve the Kaggle phishing email dataset and load the specified CSV into a DataFrame.
    Standardizes text and label columns.
    """
    dataset_dir = kagglehub.dataset_download(DATASET_HANDLE)
    file_path = os.path.join(dataset_dir, filename)

    if not os.path.exists(file_path):
        available_files = [f for f in os.listdir(dataset_dir) if f.endswith(".csv")]
        raise FileNotFoundError(
            f"Dataset file '{filename}' not found in {dataset_dir}. Available files: {available_files}"
        )

    print(f"Loading '{filename}' from {dataset_dir}...")
    df = pd.read_csv(file_path)

    # Standardize body/text and label columns
    if "body" in df.columns:
        df["text_clean"] = df["body"].fillna("")
        if "subject" in df.columns:
            df["text_clean"] = df["subject"].fillna("") + " " + df["text_clean"]
    elif "text_combined" in df.columns:
        df["text_clean"] = df["text_combined"].fillna("")
    elif "text" in df.columns:
        df["text_clean"] = df["text"].fillna("")
    else:
        df["text_clean"] = df.astype(str).agg(" ".join, axis=1)

    df["text_clean"] = df["text_clean"].str.lower()
    df["label"] = df["label"].astype(int)

    print(f"Loaded {len(df):,} records ({df['label'].sum():,} phishing, {(df['label'] == 0).sum():,} ham).")
    return df


def extract_weighted_keywords(
    df: Optional[pd.DataFrame] = None,
    output_path: str = DEFAULT_KEYWORDS_OUTPUT,
    min_weight: float = 0.50,
) -> Dict[str, dict]:
    """
    Empirically evaluate candidate phrases against the dataset to compute empirical weights
    based on the precision P(phishing | phrase), then save to output_path as JSON.
    """
    if df is None:
        df = load_email_dataset("CEAS_08.csv")

    phishing_mask = df["label"] == 1
    total_phish = int(phishing_mask.sum())
    total_ham = int((~phishing_mask).sum())

    weighted_keywords: Dict[str, dict] = {}

    # Prior domain severity baseline weights by category
    CATEGORY_BASELINES = {
        "sensitive_info": 0.90,
        "account_alert": 0.80,
        "urgency": 0.70,
        "financial": 0.70,
    }

    for phrase, category, explanation in CANDIDATE_PHRASES:
        pattern = re.escape(phrase)
        contains_phrase = df["text_clean"].str.contains(pattern, regex=True)

        n_phish = int((contains_phrase & phishing_mask).sum())
        n_ham = int((contains_phrase & ~phishing_mask).sum())
        total_occurrences = n_phish + n_ham

        baseline = CATEGORY_BASELINES.get(category, 0.60)

        # Empirical Bayesian smoothed precision: (n_phish + baseline*10) / (total_occurrences + 10)
        if total_occurrences > 0:
            empirical_ratio = (n_phish + (baseline * 10.0)) / (total_occurrences + 10.0)
            # High-risk sensitive credential solicitations preserve strong domain floor
            min_floor = 0.85 if category == "sensitive_info" else 0.40
            weight = round(min(1.0, max(min_floor, empirical_ratio)), 2)
        else:
            weight = baseline

        # Determine severity level from weight
        if weight >= 0.75:
            severity = "high"
        elif weight >= 0.45:
            severity = "medium"
        else:
            severity = "low"

        weighted_keywords[phrase] = {
            "weight": weight,
            "severity": severity,
            "category": category,
            "explanation": explanation,
            "stats": {
                "phish_count": n_phish,
                "ham_count": n_ham,
                "total": total_occurrences,
            },
        }

    # Ensure output directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(weighted_keywords, f, indent=2)

    print(f"Saved {len(weighted_keywords)} weighted keywords to {output_path}")
    return weighted_keywords


if __name__ == "__main__":
    data = load_email_dataset("CEAS_08.csv")
    print("\nFirst 3 sample records:")
    print(data[["text_clean", "label"]].head(3))

    print("\nGenerating empirical keyword weights...")
    keywords = extract_weighted_keywords(data)
    print(f"\nSample weighted keywords generated: {len(keywords)}")
    for k in list(keywords.keys())[:5]:
        item = keywords[k]
        print(f" - '{k}': weight={item['weight']}, severity={item['severity']} ({item['stats']})")
