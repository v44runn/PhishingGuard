import bisect
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

try:
    from url_checker import analyze_url
except ImportError:
    # Graceful fallback if url_checker is not found
    def analyze_url(url: str) -> dict:
        return {
            "url": url,
            "domain": url.split("//")[-1].split("/")[0],
            "score": 0.0,
            "reason": f"External link detected: {url}",
        }


# Hardcoded fallback keyword rules in case suspicious_keywords.json is absent
FALLBACK_KEYWORDS: Dict[str, dict] = {
    "account suspended": {
        "weight": 0.85,
        "severity": "high",
        "category": "account_alert",
        "explanation": "Threatens account suspension to induce panic and force rushed compliance.",
    },
    "suspended": {
        "weight": 0.70,
        "severity": "medium",
        "category": "account_alert",
        "explanation": "References account suspension, a common phishing threat to provoke panic.",
    },
    "act now": {
        "weight": 0.75,
        "severity": "high",
        "category": "urgency",
        "explanation": "Creates artificial time pressure to rush the recipient into acting without thinking.",
    },
    "urgent": {
        "weight": 0.60,
        "severity": "medium",
        "category": "urgency",
        "explanation": "Urgent language creates artificial time pressure to bypass critical verification.",
    },
    "immediate action required": {
        "weight": 0.80,
        "severity": "high",
        "category": "urgency",
        "explanation": "Pressures the recipient to act promptly without verifying the authenticity of the request.",
    },
    "within 24 hours": {
        "weight": 0.65,
        "severity": "medium",
        "category": "urgency",
        "explanation": "Imposes an artificial deadline to force hasty compliance.",
    },
    "urgent notice": {
        "weight": 0.70,
        "severity": "medium",
        "category": "urgency",
        "explanation": "Attempts to induce panic and bypass normal security scrutiny.",
    },
    "final warning": {
        "weight": 0.75,
        "severity": "medium",
        "category": "urgency",
        "explanation": "Uses intimidation and artificial scarcity to prompt an immediate response.",
    },
    "verify your account": {
        "weight": 0.85,
        "severity": "high",
        "category": "account_alert",
        "explanation": "Requests account verification, a common phishing pretext to steal credentials.",
    },
    "confirm your identity": {
        "weight": 0.75,
        "severity": "medium",
        "category": "account_alert",
        "explanation": "Prompts for personal information under the guise of an identity verification check.",
    },
    "security alert": {
        "weight": 0.75,
        "severity": "medium",
        "category": "account_alert",
        "explanation": "Impersonates security teams to establish false authority and create alarm.",
    },
    "unauthorized login": {
        "weight": 0.80,
        "severity": "high",
        "category": "account_alert",
        "explanation": "Fake security alert designed to provoke panicked credential submission.",
    },
    "enter your password": {
        "weight": 0.95,
        "severity": "high",
        "category": "sensitive_info",
        "explanation": "Directly solicits account passwords, which legitimate organizations never request via email.",
    },
    "send your password": {
        "weight": 0.95,
        "severity": "high",
        "category": "sensitive_info",
        "explanation": "Directly asks recipient to send passwords, a clear credential harvesting indicator.",
    },
    "password": {
        "weight": 0.70,
        "severity": "medium",
        "category": "sensitive_info",
        "explanation": "Mentions passwords, frequently targeted in credential harvesting schemes.",
    },
    "confirm your ssn": {
        "weight": 0.95,
        "severity": "high",
        "category": "sensitive_info",
        "explanation": "Requests Social Security Number, highly sensitive PII used for identity theft.",
    },
    "social security": {
        "weight": 0.75,
        "severity": "medium",
        "category": "sensitive_info",
        "explanation": "References Social Security details, which should never be shared over unencrypted email.",
    },
    "banking credentials": {
        "weight": 0.90,
        "severity": "high",
        "category": "sensitive_info",
        "explanation": "Requests confidential banking login information.",
    },
    "credit card number": {
        "weight": 0.85,
        "severity": "high",
        "category": "sensitive_info",
        "explanation": "Solicits payment card numbers to conduct unauthorized transactions.",
    },
    "seed phrase": {
        "weight": 0.95,
        "severity": "high",
        "category": "sensitive_info",
        "explanation": "Requests cryptocurrency secret recovery phrase; guarantees wallet theft.",
    },
    "verification code": {
        "weight": 0.75,
        "severity": "medium",
        "category": "sensitive_info",
        "explanation": "Attempts to intercept Multi-Factor Authentication (MFA/2FA) one-time codes.",
    },
    "wire transfer": {
        "weight": 0.70,
        "severity": "medium",
        "category": "financial",
        "explanation": "Often indicates Business Email Compromise (BEC) or urgent payment diversion scams.",
    },
}


def _load_keywords() -> Dict[str, dict]:
    """
    Load suspicious keywords and their empirical weights from suspicious_keywords.json.
    Falls back to built-in rules if file is missing or invalid.
    """
    possible_paths = [
        os.path.join(os.path.dirname(__file__), "suspicious_keywords.json"),
        os.path.join(os.getcwd(), "suspicious_keywords.json"),
        os.path.join(os.getcwd(), "detector", "suspicious_keywords.json"),
    ]
    for path in possible_paths:
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict) and data:
                        return data
            except Exception:
                pass
    return FALLBACK_KEYWORDS


# Initialize module-level keyword cache and compiled patterns (zero per-call I/O)
KEYWORDS_DATA = _load_keywords()

# Compile keyword regexes sorted by length descending so longer specific phrases match first
_SORTED_PHRASES = sorted(KEYWORDS_DATA.keys(), key=lambda p: len(p), reverse=True)
_KEYWORD_REGEXES: List[Tuple[str, re.Pattern, dict]] = [
    (phrase, re.compile(rf"\b{re.escape(phrase)}\b", re.IGNORECASE), KEYWORDS_DATA[phrase])
    for phrase in _SORTED_PHRASES
]

# Fast regex to identify URL candidates
_URL_REGEX = re.compile(r"https?://[^\s<>\"')]+|www\.[^\s<>\"')]+", re.IGNORECASE)


def _get_line_number(newline_indices: List[int], char_index: int) -> int:
    """Return 1-based line number for a character offset using binary search."""
    return bisect.bisect_right(newline_indices, char_index) + 1


def analyze_email(text: str) -> List[dict]:
    """
    Screen an email text for suspicious red flags using fast algorithmic heuristics.
    High-throughput first-pass filter designed to cheaply triage emails.

    Args:
        text (str): The raw email text to analyze.

    Returns:
        List[dict]: List of detected warnings with location offsets and explanations.
            Each dictionary contains:
            - warning (str): Title/category of the red flag
            - explanation (str): Why this pattern is dangerous
            - start (int): 0-based character start index
            - end (int): 0-based character end index
            - line (int): 1-based line number in email
            - line_number (int): 1-based line number (for app.py compatibility)
            - matched_text (str): Exact substring matched
            - text (str): Exact substring matched (for app.py compatibility)
            - weight (float): Weighted threat value (0.0 to 1.0)
            - severity (str): "low", "medium", or "high"
    """
    warnings: List[dict] = []

    if not text or not isinstance(text, str):
        return warnings

    # Precalculate newline indices for fast O(log N) line number resolution
    newline_indices = [i for i, char in enumerate(text) if char == "\n"]

    # Track matched spans to avoid duplicate or nested sub-phrase warnings
    matched_spans: List[Tuple[int, int]] = []

    # 1. Check for weighted suspicious keywords & phrases
    for phrase, pattern, meta in _KEYWORD_REGEXES:
        for match in pattern.finditer(text):
            start, end = match.span()

            # Skip if this match is wholly contained in an already matched longer phrase
            if any(s <= start and end <= e for s, e in matched_spans):
                continue

            matched_spans.append((start, end))

            category = meta.get("category", "suspicious_keyword")
            category_titles = {
                "urgency": "Urgent language detected",
                "account_alert": "Account alert / verification request",
                "sensitive_info": "Requests sensitive credentials",
                "financial": "Financial lure detected",
            }
            warning_title = category_titles.get(category, "Suspicious pattern detected")
            line_num = _get_line_number(newline_indices, start)

            warnings.append(
                {
                    "warning": warning_title,
                    "explanation": meta.get(
                        "explanation",
                        f"Matched suspicious phishing indicator '{match.group()}'."
                    ),
                    "start": start,
                    "end": end,
                    "line": line_num,
                    "line_number": line_num,
                    "matched_text": match.group(),
                    "text": match.group(),
                    "weight": float(meta.get("weight", 0.70)),
                    "severity": meta.get("severity", "medium"),
                }
            )

    # 2. Extract links and delegate risk evaluation to url_checker.analyze_url
    # Quick pre-check: only scan if link prefixes are present
    text_lower = text.lower()
    if "http://" in text_lower or "https://" in text_lower or "www." in text_lower:
        for match in _URL_REGEX.finditer(text):
            start, end = match.span()
            matched_url = match.group()

            # Clean trailing punctuation often caught at end of sentences
            while matched_url and matched_url[-1] in ".,!?:;":
                matched_url = matched_url[:-1]
                end -= 1

            if not matched_url:
                continue

            line_num = _get_line_number(newline_indices, start)

            # Outsource URL risk assessment to url_checker
            try:
                url_data = analyze_url(matched_url)
            except Exception as e:
                url_data = {
                    "url": matched_url,
                    "domain": matched_url,
                    "score": 0.0,
                    "reason": f"External link detected: {matched_url} (Analysis error: {e})",
                }

            score = float(url_data.get("score", 0.0))
            reason = url_data.get("reason", f"Link pointing to {url_data.get('domain', matched_url)}")

            if score > 0:
                weight = min(1.0, max(0.1, round(score / 100.0, 2)))
                severity = "high" if score >= 75 else ("medium" if score >= 45 else "low")
                warning_title = "Suspicious URL detected"
            else:
                weight = 0.10
                severity = "low"
                warning_title = "Link detected"

            warnings.append(
                {
                    "warning": warning_title,
                    "explanation": reason,
                    "start": start,
                    "end": end,
                    "line": line_num,
                    "line_number": line_num,
                    "matched_text": matched_url,
                    "text": matched_url,
                    "weight": weight,
                    "severity": severity,
                }
            )

    # Sort warnings chronologically by appearance in text
    warnings.sort(key=lambda w: (w["start"], -w["weight"]))
    return warnings


# Alias for compatibility with app.py
detect_red_flags = analyze_email
