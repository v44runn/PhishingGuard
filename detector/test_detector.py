import os
import time
import unittest
from unittest.mock import patch

from detector import analyze_email, detect_red_flags, _load_keywords, FALLBACK_KEYWORDS


class TestDetector(unittest.TestCase):

    def test_clean_email(self):
        """Safe emails with no red flags should return an empty warning list."""
        clean_text = "Hi Alice, could we schedule our project check-in meeting for tomorrow at 2 PM? Thanks!"
        warnings = analyze_email(clean_text)
        self.assertEqual(warnings, [])

    def test_empty_or_invalid_input(self):
        """Empty text or non-string inputs should return an empty list without error."""
        self.assertEqual(analyze_email(""), [])
        self.assertEqual(analyze_email(None), [])
        self.assertEqual(analyze_email(12345), [])

    def test_urgent_language_detection(self):
        """Urgent language like 'act now' should be detected with accurate location."""
        text = "Important update: Please act now to secure your profile."
        warnings = analyze_email(text)
        self.assertGreater(len(warnings), 0)

        urgent_warn = next((w for w in warnings if w["matched_text"].lower() == "act now"), None)
        self.assertIsNotNone(urgent_warn)
        self.assertEqual(urgent_warn["warning"], "Urgent language detected")
        self.assertEqual(text[urgent_warn["start"]:urgent_warn["end"]], "act now")
        self.assertEqual(urgent_warn["line_number"], 1)
        self.assertEqual(urgent_warn["line"], text)
        self.assertEqual(urgent_warn["text"], "act now")
        self.assertIn("urgency", urgent_warn["explanation"].lower())
        self.assertIn(urgent_warn["severity"], ["low", "medium", "high"])
        self.assertTrue(0.0 <= urgent_warn["weight"] <= 1.0)

    def test_account_suspended_detection(self):
        """Account suspension alerts should be flagged with appropriate category and explanation."""
        text = "Notice: Your account suspended due to unusual activity."
        warnings = analyze_email(text)
        self.assertGreater(len(warnings), 0)

        alert_warn = next((w for w in warnings if w["matched_text"].lower() == "account suspended"), None)
        self.assertIsNotNone(alert_warn)
        self.assertEqual(alert_warn["warning"], "Account alert / verification request")
        self.assertEqual(text[alert_warn["start"]:alert_warn["end"]], "account suspended")
        self.assertEqual(alert_warn["line_number"], 1)
        self.assertEqual(alert_warn["line"], text)
        self.assertIn("suspension", alert_warn["explanation"].lower())

    def test_nested_phrases_deduplication(self):
        """More specific phrases (e.g. 'account suspended') should not trigger redundant sub-phrase ('suspended') matches."""
        text = "Your account suspended today."
        warnings = analyze_email(text)
        matched_texts = [w["matched_text"].lower() for w in warnings]
        self.assertIn("account suspended", matched_texts)
        self.assertNotIn("suspended", matched_texts)

    def test_sensitive_information_requests(self):
        """Requests for passwords or sensitive personal data must be flagged."""
        text = "To resolve this issue, please enter your password and confirm your ssn."
        warnings = analyze_email(text)
        self.assertGreaterEqual(len(warnings), 2)

        matched_phrases = {w["matched_text"].lower(): w for w in warnings}
        self.assertIn("enter your password", matched_phrases)
        self.assertIn("confirm your ssn", matched_phrases)

        pw_warn = matched_phrases["enter your password"]
        self.assertEqual(pw_warn["warning"], "Requests sensitive credentials")
        self.assertEqual(text[pw_warn["start"]:pw_warn["end"]], "enter your password")
        self.assertEqual(pw_warn["severity"], "high")

    def test_multiline_location_accuracy(self):
        """Line numbers and char offsets must accurately reflect multi-line emails."""
        text = (
            "Dear Customer,\n"                       # Line 1
            "We detected unusual activity.\n"        # Line 2
            "Please act now to avoid disruption.\n"  # Line 3
            "Thank you."                             # Line 4
        )
        warnings = analyze_email(text)
        urgent_warn = next(w for w in warnings if w["matched_text"].lower() == "act now")
        self.assertEqual(urgent_warn["line_number"], 3)
        self.assertEqual(urgent_warn["line"], "Please act now to avoid disruption.")
        self.assertEqual(text[urgent_warn["start"]:urgent_warn["end"]], "act now")

    def test_app_py_compatibility_schema(self):
        """Verify that findings conform strictly to all keys expected by app.py UI rendering."""
        text = "Urgent: verify your account at https://google.com"
        findings = detect_red_flags(text)
        self.assertGreater(len(findings), 0)

        required_keys = {"start", "end", "line_number", "text", "line", "explanation"}
        for f in findings:
            self.assertTrue(required_keys.issubset(f.keys()), f"Finding missing required keys: {f}")
            self.assertIsInstance(f["start"], int)
            self.assertIsInstance(f["end"], int)
            self.assertIsInstance(f["line_number"], int)
            self.assertIsInstance(f["text"], str)
            self.assertIsInstance(f["line"], str)
            self.assertIsInstance(f["explanation"], str)

    def test_link_detection_and_url_checker_delegation(self):
        """Links should be extracted and delegated to url_checker.analyze_url."""
        text = "Click here to view your invoice: https://billing.example.com/pay"
        warnings = analyze_email(text)
        link_warn = next(w for w in warnings if "billing.example.com" in w["matched_text"])
        self.assertIsNotNone(link_warn)
        self.assertEqual(link_warn["matched_text"], "https://billing.example.com/pay")
        self.assertEqual(text[link_warn["start"]:link_warn["end"]], "https://billing.example.com/pay")
        self.assertEqual(link_warn["warning"], "Link detected")

    def test_suspicious_url_mocking(self):
        """When url_checker returns a high risk score, the warning should reflect suspicious URL."""
        text = "Login here: http://192.168.1.1/secure/login"
        with patch("detector.detector.analyze_url") as mock_analyze:
            mock_analyze.return_value = {
                "url": "http://192.168.1.1/secure/login",
                "domain": "192.168.1.1",
                "score": 90.0,
                "reasons": ["URL uses a raw IP address instead of a domain name."],
            }
            warnings = analyze_email(text)
            url_warn = next(w for w in warnings if "192.168.1.1" in w["matched_text"])
            self.assertEqual(url_warn["warning"], "Suspicious URL detected")
            self.assertEqual(url_warn["severity"], "high")
            self.assertEqual(url_warn["weight"], 0.90)
            self.assertIn("raw IP address", url_warn["explanation"])

    def test_real_url_checker_integration(self):
        """Verify integration with the real url_checker module without mocking."""
        text = "Phishing alert: visit http://192.168.1.1/login"
        warnings = analyze_email(text)
        url_warn = next((w for w in warnings if "192.168.1.1" in w["matched_text"]), None)
        self.assertIsNotNone(url_warn)
        self.assertEqual(url_warn["warning"], "Suspicious URL detected")
        self.assertIn("IP address", url_warn["explanation"])

    def test_fallback_keywords(self):
        """Ensure detector functions even if keywords json path is missing."""
        with patch("os.path.isfile", return_value=False):
            keywords = _load_keywords()
            self.assertEqual(keywords, FALLBACK_KEYWORDS)

    def test_url_punctuation_stripping(self):
        """Trailing punctuation like commas, periods, exclamation marks should not be included in URL bounds."""
        text = "Visit https://paypal.com/login, and also www.google.com!"
        warnings = analyze_email(text)
        urls = [w["matched_text"] for w in warnings if w["warning"] in ["Link detected", "Suspicious URL detected"]]
        self.assertIn("https://paypal.com/login", urls)
        self.assertIn("www.google.com", urls)
        for w in warnings:
            if w["matched_text"] in urls:
                self.assertEqual(text[w["start"]:w["end"]], w["matched_text"])

    def test_url_checker_exception_resilience(self):
        """If url_checker raises an exception, analyze_email should safely degrade rather than crash."""
        text = "Check this out: https://broken-link.com"
        with patch("detector.detector.analyze_url", side_effect=RuntimeError("Network timeout")):
            warnings = analyze_email(text)
            self.assertEqual(len(warnings), 1)
            self.assertEqual(warnings[0]["warning"], "Link detected")
            self.assertIn("broken-link.com", warnings[0]["matched_text"])

    def test_high_throughput_benchmark(self):
        """Verify detector can analyze thousands of emails per second."""
        sample_email = (
            "Dear User,\n"
            "Your account suspended due to unauthorized login.\n"
            "Please act now and verify your account at https://secure-login.test.com.\n"
            "Failure to respond within 24 hours will result in permanent lock."
        )
        iterations = 5000
        start_time = time.perf_counter()
        for _ in range(iterations):
            _ = analyze_email(sample_email)
        elapsed = time.perf_counter() - start_time

        emails_per_sec = iterations / elapsed
        print(f"\n[Performance Benchmark] {iterations} emails screened in {elapsed:.3f}s ({emails_per_sec:,.0f} emails/sec)")
        self.assertGreater(emails_per_sec, 1000)  # Must achieve > 1,000 emails/sec


if __name__ == "__main__":
    unittest.main()
